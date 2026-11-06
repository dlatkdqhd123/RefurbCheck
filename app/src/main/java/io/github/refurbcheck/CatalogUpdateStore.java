package io.github.refurbcheck;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.StandardCopyOption;

/**
 * Application-private, single-snapshot store. Validates before mutation and uses
 * a same-directory atomic rename, never an in-place write of the active ZIP.
 * The private rollback floor survives removal/corruption of just the active ZIP.
 * It cannot survive clearing app data or a hostile OS restoring all private data.
 */
final class CatalogUpdateStore {
    private final File directory,active,floorFile;
    private final byte[] publicKey;
    private final Floor shippedFloor;
    static final class Stored {
        final CatalogUpdateVerifier.Snapshot snapshot;
        final String error;
        Stored(CatalogUpdateVerifier.Snapshot snapshot,String error) {this.snapshot=snapshot;this.error=error;}
    }
    static final class Applied {
        final CatalogUpdateVerifier.Snapshot snapshot;
        final boolean changed;
        final String warning;
        Applied(CatalogUpdateVerifier.Snapshot snapshot,boolean changed,String warning) {
            this.snapshot=snapshot;this.changed=changed;this.warning=warning;
        }
    }
    private static final class Floor {
        final long sequence;final String sha256;
        Floor(long sequence,String sha256) {this.sequence=sequence;this.sha256=sha256;}
    }
    CatalogUpdateStore(File directory,byte[] publicKey,long shippedSequence,String shippedBundleSha256) throws IOException {
        if(directory==null||publicKey==null||shippedSequence<1||!ApkEvidence.validSha256(shippedBundleSha256))
            throw new IOException("CATALOG_STORE_CONFIGURATION");
        this.directory=directory;active=new File(directory,"active.zip");floorFile=new File(directory,"rollback-floor.json");
        this.publicKey=publicKey.clone();shippedFloor=new Floor(shippedSequence,shippedBundleSha256);
        if(Files.isSymbolicLink(directory.toPath())) throw new IOException("CATALOG_STORE_DIRECTORY_LINK");
        if(!directory.isDirectory()&&!directory.mkdirs()) throw new IOException("CATALOG_STORE_DIRECTORY_UNAVAILABLE");
    }

    synchronized Stored read(long now,ApkEvidence.Budget budget) {
        try {
            Floor floor=readFloor(budget);
            if(!Files.exists(active.toPath(),LinkOption.NOFOLLOW_LINKS)) return new Stored(null,floor.sequence>shippedFloor.sequence?"CATALOG_ACTIVE_MISSING_AFTER_UPDATE":"");
            CatalogUpdateVerifier.Snapshot snapshot=CatalogUpdateVerifier.verify(read(active,CatalogUpdateVerifier.MAX_BUNDLE_BYTES,budget),
                    publicKey,floor.sequence,floor.sha256,now,false,budget);
            String error="";
            if(snapshot.sequence>floor.sequence) {
                try {writeFloor(snapshot);} catch(IOException stateFailure) {error="CATALOG_ROLLBACK_STATE_REPAIR_FAILED";}
            }
            return new Stored(snapshot,error);
        } catch(Exception error) {return new Stored(null,error.getClass().getSimpleName()+": "+error.getMessage());}
    }

    synchronized Applied install(byte[] bundle,long now,ApkEvidence.Budget budget) throws IOException {
        Floor floor=readFloor(budget);CatalogUpdateVerifier.Snapshot previous=null;
        if(Files.exists(active.toPath(),LinkOption.NOFOLLOW_LINKS)) {
            try {
                previous=CatalogUpdateVerifier.verify(read(active,CatalogUpdateVerifier.MAX_BUNDLE_BYTES,budget),
                        publicKey,floor.sequence,floor.sha256,now,false,budget);
                if(previous.sequence>floor.sequence) floor=new Floor(previous.sequence,previous.bundleSha256);
            } catch(IOException unreadable) {
                // A newer independently authenticated update can repair a bad active
                // file, but cannot lower the separately retained accepted floor.
                budget.check();
            }
        }
        CatalogUpdateVerifier.Snapshot candidate=CatalogUpdateVerifier.verify(bundle,publicKey,floor.sequence,floor.sha256,now,true,budget);
        boolean same=previous!=null&&candidate.bundleSha256.equals(previous.bundleSha256);
        if(!same) {
            budget.check();
            atomicWrite(active,bundle); // Failure before rename preserves the previous file.
        }
        String warning="";
        try {writeFloor(candidate);} catch(IOException failure) {
            // The active ZIP is already authenticated and contains the version.
            // read() will recover its floor; until then this warning blocks auto-removal.
            warning="CATALOG_ROLLBACK_STATE_WRITE_FAILED";
        }
        return new Applied(candidate,!same,warning);
    }

    private Floor readFloor(ApkEvidence.Budget budget) throws IOException {
        if(!Files.exists(floorFile.toPath(),LinkOption.NOFOLLOW_LINKS)) return shippedFloor;
        try {
            JSONObject json=ReportJson.parse(read(floorFile,4096,budget));
            if(json.length()!=3||!"refurbcheck-catalog-floor-v1".equals(CatalogUpdateVerifier.string(json,"schema")))
                throw new IOException("CATALOG_ROLLBACK_STATE_INVALID");
            long sequence=CatalogUpdateVerifier.integer(json,"sequence",1,1_000_000_000L);
            String digest=CatalogUpdateVerifier.string(json,"bundleSha256");
            if(!digest.matches("[0-9a-f]{64}")) throw new IOException("CATALOG_ROLLBACK_STATE_DIGEST_INVALID");
            if(sequence<shippedFloor.sequence) return shippedFloor; // A later app can raise the baked-in floor.
            if(sequence==shippedFloor.sequence&&!digest.equals(shippedFloor.sha256))
                throw new IOException("CATALOG_SHIPPED_FLOOR_CONFLICT");
            return new Floor(sequence,digest);
        } catch(IOException damaged) {
            budget.check();
            throw new IOException("CATALOG_ROLLBACK_STATE_INVALID",damaged);
        }
    }
    private void writeFloor(CatalogUpdateVerifier.Snapshot snapshot) throws IOException {
        String json="{\"schema\":\"refurbcheck-catalog-floor-v1\",\"sequence\":"+snapshot.sequence
                +",\"bundleSha256\":\""+snapshot.bundleSha256+"\"}\n";
        atomicWrite(floorFile,json.getBytes(StandardCharsets.UTF_8));
    }
    private static byte[] read(File file,int maximum,ApkEvidence.Budget budget) throws IOException {
        if(!Files.isRegularFile(file.toPath(),LinkOption.NOFOLLOW_LINKS)||file.length()>maximum)
            throw new IOException("CATALOG_PRIVATE_FILE_INVALID");
        try(FileInputStream input=new FileInputStream(file)) {return CatalogUpdateVerifier.readBounded(input,maximum,budget);}
    }
    private void atomicWrite(File target,byte[] bytes) throws IOException {
        if(Files.isSymbolicLink(target.toPath())) throw new IOException("CATALOG_PRIVATE_FILE_LINK");
        File pending=File.createTempFile("catalog-",".pending",directory);
        try {
            try(FileOutputStream output=new FileOutputStream(pending)) {output.write(bytes);output.getFD().sync();}
            // Refuse to fall back to copy/truncate if the filesystem cannot rename atomically.
            Files.move(pending.toPath(),target.toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        } finally {if(pending.exists()) pending.delete();}
    }
}
