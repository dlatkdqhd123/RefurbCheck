package io.github.refurbcheck;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;

/** Pure helpers for bounded file evidence. None of these checks certifies malware absence. */
public final class ApkEvidence {
    public static final long DEFAULT_TIME_MILLIS=180_000L;
    public static final long MAX_FILE_BYTES=1L<<30;
    public static final long MAX_TOTAL_BYTES=8L<<30;
    public static final int ENGINE_MAX_API=33;
    public static final String ENGINE_VERSION="apksig-android 4.4.0 (2022-10-15 source; API <=33 model)";
    public static final String IOC_COMMIT="b22ddf05e1a31e7732b8895676987c5c3482ef65";
    public static final String IOC_ASSET_SHA256="0ba51e936f40449d1c86f7408624a2da5950b21ec214c4b62209a3a269a81278";
    public static final String IOC_REPOSITORY="https://github.com/mvt-project/mvt-indicators";
    public static final int IOC_ENTRY_COUNT=156;
    private ApkEvidence() { }

    public static final class LimitException extends IOException {
        public final String reason;
        public LimitException(String reason) { super(reason); this.reason=reason; }
    }

    /** The total byte limit covers both hashing and verifier reads, including rereads. */
    public static final class Budget {
        private final long deadline, maximumBytes;
        private final AtomicBoolean cancelled;
        private final LongSupplier nanoTime;
        private long hashBytes, signatureBytes, archiveBytes;
        public Budget(AtomicBoolean cancelled) {
            this(cancelled,DEFAULT_TIME_MILLIS,MAX_TOTAL_BYTES,System::nanoTime);
        }
        public Budget(AtomicBoolean cancelled,long millis,long maximumBytes,LongSupplier nanoTime) {
            if(millis<=0||maximumBytes<0||millis>Long.MAX_VALUE/1_000_000L)
                throw new IllegalArgumentException("invalid budget");
            this.cancelled=cancelled==null?new AtomicBoolean(false):cancelled;
            this.maximumBytes=maximumBytes;
            this.nanoTime=nanoTime;
            deadline=nanoTime.getAsLong()+millis*1_000_000L;
        }
        public synchronized void check() throws LimitException {
            if(cancelled.get()||Thread.currentThread().isInterrupted()) throw new LimitException("CANCELLED");
            if(nanoTime.getAsLong()-deadline>=0) throw new LimitException("TIME_LIMIT");
        }
        public synchronized int allowedRead(int requested) throws LimitException {
            check();
            long remaining=maximumBytes-hashBytes-signatureBytes-archiveBytes;
            if(requested>0&&remaining<=0) throw new LimitException("TOTAL_BYTE_LIMIT");
            return (int)Math.min(requested,remaining);
        }
        public synchronized void read(long count,boolean signature) throws LimitException {
            if(count<0||count>maximumBytes-hashBytes-signatureBytes-archiveBytes) throw new LimitException("TOTAL_BYTE_LIMIT");
            if(signature) signatureBytes+=count; else hashBytes+=count;
            check();
        }
        public synchronized long hashBytesRead() { return hashBytes; }
        public synchronized long signatureBytesRead() { return signatureBytes; }
        /** Compressed ZIP reads, including headers and rereads, share the same total budget. */
        public synchronized void readArchive(long count) throws LimitException {
            if(count<0||count>maximumBytes-hashBytes-signatureBytes-archiveBytes) throw new LimitException("TOTAL_BYTE_LIMIT");
            archiveBytes+=count;
            check();
        }
        public synchronized long archiveBytesRead() { return archiveBytes; }
    }

    public static String sha256(byte[] data) {
        return hex(digest().digest(data));
    }
    private static MessageDigest digest() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch(NoSuchAlgorithmException e) { throw new IllegalStateException("SHA-256 unavailable",e); }
    }
    public static String hex(byte[] data) {
        char[] hex="0123456789abcdef".toCharArray(), result=new char[data.length*2];
        for(int i=0;i<data.length;i++) { result[i*2]=hex[(data[i]>>>4)&15]; result[i*2+1]=hex[data[i]&15]; }
        return new String(result);
    }
    public static boolean validSha256(String value) { return value!=null&&value.matches("(?i)[0-9a-f]{64}"); }

    /** Reads exactly the stated file length and rejects truncation or growth. */
    public static String hash(InputStream input,long expectedSize,Budget budget) throws IOException {
        budget.check();
        if(expectedSize<0) throw new IOException("UNKNOWN_SIZE");
        if(expectedSize>MAX_FILE_BYTES) throw new LimitException("FILE_BYTE_LIMIT");
        MessageDigest md=digest();
        byte[] buffer=new byte[64*1024];
        long seen=0; int stalls=0;
        while(seen<expectedSize) {
            int request=budget.allowedRead((int)Math.min(buffer.length,expectedSize-seen));
            int count=input.read(buffer,0,request);
            if(count<0) throw new IOException("FILE_TRUNCATED");
            if(count==0) { if(++stalls>3) throw new IOException("READ_STALLED"); continue; }
            stalls=0; budget.read(count,false); md.update(buffer,0,count); seen+=count;
        }
        budget.check();
        // A successful EOF probe does not consume the byte budget. Growth is never accepted.
        int extra=input.read();
        if(extra!=-1) { budget.read(1,false); throw new IOException("FILE_GREW"); }
        budget.check();
        return hex(md.digest());
    }

    public static final class Stamp {
        public final long size,mtime,ctime,device,inode;
        public final boolean identityAvailable;
        public Stamp(long size,long mtime,long ctime,long device,long inode,boolean identityAvailable) {
            this.size=size; this.mtime=mtime; this.ctime=ctime; this.device=device; this.inode=inode;
            this.identityAvailable=identityAvailable;
        }
        public boolean same(Stamp other) {
            return other!=null&&size==other.size&&mtime==other.mtime&&ctime==other.ctime
                    &&identityAvailable==other.identityAvailable
                    &&(!identityAvailable||(device==other.device&&inode==other.inode));
        }
    }

    public static final class IocIndex {
        private final Map<String,List<String>> entries;
        public final String fileSha256;
        public final int entryCount;
        private IocIndex(Map<String,List<String>> entries,String fileSha256,int count) {
            this.entries=entries; this.fileSha256=fileSha256; this.entryCount=count;
        }
        public List<String> match(String sha256) {
            if(!validSha256(sha256)) return Collections.emptyList();
            List<String> value=entries.get(sha256.toLowerCase(Locale.ROOT));
            return value==null?Collections.emptyList():value;
        }
        public int uniqueHashes() { return entries.size(); }
    }

    /** Strict, digest-pinned parsing: malformed or empty databases cannot become a no-match result. */
    public static IocIndex parseIocs(byte[] bytes,String expectedSha256,Set<String> allowedCollections) throws IOException {
        if(bytes.length>128*1024) throw new IOException("IOC_FILE_TOO_LARGE");
        if(!validSha256(expectedSha256)||!sha256(bytes).equalsIgnoreCase(expectedSha256))
            throw new IOException("IOC_DIGEST_MISMATCH");
        Map<String,List<String>> index=new LinkedHashMap<>(); Set<String> pairs=new LinkedHashSet<>(); int count=0;
        InputStreamReader decoder=new InputStreamReader(new ByteArrayInputStream(bytes),
                StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT));
        try(BufferedReader reader=new BufferedReader(decoder)) {
            String line;
            while((line=reader.readLine())!=null) {
                if(line.startsWith("#")||line.trim().isEmpty()) continue;
                String[] cols=line.split("\t",-1);
                if(cols.length!=2||!validSha256(cols[0])||!allowedCollections.contains(cols[1]))
                    throw new IOException("IOC_MALFORMED_ROW");
                String hash=cols[0].toLowerCase(Locale.ROOT), pair=hash+":"+cols[1];
                if(!pairs.add(pair)) throw new IOException("IOC_DUPLICATE_ROW");
                List<String> collections=index.get(hash);
                if(collections==null) { collections=new ArrayList<>(); index.put(hash,collections); }
                collections.add(cols[1]); count++;
            }
        }
        if(count==0) throw new IOException("IOC_EMPTY_DATABASE");
        Map<String,List<String>> frozen=new LinkedHashMap<>();
        for(Map.Entry<String,List<String>> e:index.entrySet()) frozen.put(e.getKey(),Collections.unmodifiableList(e.getValue()));
        return new IocIndex(Collections.unmodifiableMap(frozen),sha256(bytes),count);
    }
    public static IocIndex bundledIocs(byte[] bytes) throws IOException {
        Set<String> allowed=new LinkedHashSet<>(); allowed.add("btmob"); allowed.add("eaglemsgspy");
        IocIndex result=parseIocs(bytes,IOC_ASSET_SHA256,allowed);
        if(result.entryCount!=IOC_ENTRY_COUNT) throw new IOException("IOC_COUNT_MISMATCH");
        return result;
    }
    public static String collectionName(String collection) {
        if("btmob".equals(collection)) return "BTMOB Android RAT";
        if("eaglemsgspy".equals(collection)) return "EagleMsgSpy Android surveillanceware";
        return "Unknown collection";
    }
    public static String collectionSource(String collection) {
        String path="btmob".equals(collection)?"2026-05-26_btmob":"eaglemsgspy".equals(collection)?"2024-12-25_eaglemsgspy":"";
        return path.isEmpty()?"":IOC_REPOSITORY+"/blob/"+IOC_COMMIT+"/"+path+"/sha256.txt";
    }

    public static boolean sameSignerSets(List<String> left,List<String> right) {
        if(left==null||right==null||left.isEmpty()||right.isEmpty()) return false;
        Set<String> a=new LinkedHashSet<>(),b=new LinkedHashSet<>();
        for(String value:left) { if(!validSha256(value)) return false; a.add(value.toLowerCase(Locale.ROOT)); }
        for(String value:right) { if(!validSha256(value)) return false; b.add(value.toLowerCase(Locale.ROOT)); }
        return a.equals(b);
    }

    /** An old verifier's Android model never becomes a pass on a newer platform. */
    public static String signatureStatus(boolean verified,List<String> errors,int deviceApi) {
        if(deviceApi>ENGINE_MAX_API||deviceApi<26) return "UNKNOWN_PLATFORM";
        for(String error:errors) if(error.contains("UNSUPPORTED")||error.contains("NO_SUPPORTED")
                ||error.contains("UNKNOWN")||error.contains("EXCEPTION")) return "UNKNOWN_UNSUPPORTED";
        if(verified) return "VERIFIED";
        return errors.isEmpty()?"UNKNOWN_VERIFIER":"INVALID";
    }
}
