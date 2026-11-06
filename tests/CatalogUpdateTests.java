package io.github.refurbcheck;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Negative transfer/storage fixtures use ephemeral keys and harmless text, never shipped IOCs. */
public final class CatalogUpdateTests {
    private static final long NOW=1794009600000L,DAY=86400000L;
    private static final String[] FILES={"malware_catalog.json","malware_clamav.tsv","malware_eset.tsv","malware_echap.tsv","malware_mvt.tsv","malware_clamav_allow.tsv"};
    private static final String[] SOURCES={"clamav.android","eset.android","echap.stalkerware","mvt.android","clamav.allow"};
    private static final String[] LICENSES={"GPL-2.0-only","BSD-2-Clause","CC-BY-4.0","MIT","GPL-2.0-only"};
    private static int scenarios,assertions,failures;
    private static KeyPair key;
    private interface Check {void run() throws Exception;}
    public static void main(String[] args) throws Exception {
        key=key(3072);Fixture fixture=new Fixture();byte[] valid=fixture.bundle();
        scenario("current signed data validates, parses and does not become executable rules",()->{
            CatalogUpdateVerifier.Snapshot value=verify(valid,0,"",NOW,true);
            same(4,value.entryCount);same(1,value.allowEntryCount);same(1L,value.sequence);yes(value.signedUpdate);
            same("CURRENT",value.freshness(NOW));same("2026-11-06",value.snapshotDate);
            same(ApkEvidence.sha256(valid),value.bundleSha256);
        });
        scenario("metadata getter cannot mutate the retained snapshot",()->{
            CatalogUpdateVerifier.Snapshot value=verify(valid,0,"",NOW,true);
            value.metadata().put("snapshotDate","untrusted mutation");same("2026-11-06",value.metadata().getString("snapshotDate"));
        });
        scenario("identical accepted sequence and bundle is idempotent",()->same(1L,verify(valid,1,ApkEvidence.sha256(valid),NOW,true).sequence));
        scenario("lower signed sequence cannot roll back a higher accepted floor",()->rejects("ROLLBACK",()->verify(valid,2,ApkEvidence.sha256(valid),NOW,true)));
        scenario("same sequence with a different correctly signed payload is equivocation",()->{
            Fixture different=new Fixture();different.created=NOW-2000;
            rejects("SEQUENCE_CONFLICT",()->verify(different.bundle(),1,ApkEvidence.sha256(valid),NOW,true));
        });
        scenario("later sequence accepted without requiring the old content digest",()->{
            Fixture later=new Fixture();later.sequence=2;same(2L,verify(later.bundle(),1,ApkEvidence.sha256(valid),NOW,true).sequence);
        });
        scenario("signature authenticates exact manifest bytes including domain separation",()->{
            Fixture bad=new Fixture();bad.signatureOverride=new byte[384];rejects("SIGNATURE",()->verify(bad.bundle(),0,"",NOW,true));
            Fixture noContext=new Fixture();noContext.signWithoutContext=true;
            rejects("SIGNATURE",()->verify(noContext.bundle(),0,"",NOW,true));
        });
        scenario("another RSA key cannot authorize an update",()->{
            KeyPair other=key(3072);rejects("SIGNATURE",()->CatalogUpdateVerifier.verify(valid,other.getPublic().getEncoded(),0,"",NOW,true,budget()));
        });
        scenario("key/signature type and size are fixed",()->{
            KeyPair small=key(2048);Fixture weak=new Fixture();weak.signingKey=small;
            rejects("KEY_OR_SIGNATURE_SIZE",()->CatalogUpdateVerifier.verify(weak.bundle(),small.getPublic().getEncoded(),0,"",NOW,true,budget()));
            rejects("PUBLIC_KEY",()->CatalogUpdateVerifier.verify(valid,new byte[0],0,"",NOW,true,budget()));
        });
        scenario("expired imports rejected but stored authentic data can be marked stale",()->{
            rejects("UPDATE_EXPIRED",()->verify(valid,0,"",NOW+30*DAY,true));
            same("EXPIRED",verify(valid,0,"",NOW+30*DAY,false).freshness(NOW+30*DAY));
        });
        scenario("expiry boundary is exclusive",()->rejects("UPDATE_EXPIRED",()->verify(valid,0,"",fixture.created+30*DAY,true)));
        scenario("future dated updates and rolled-back device time fail closed",()->{
            Fixture future=new Fixture();future.created=NOW+CatalogUpdateVerifier.CLOCK_SKEW_MILLIS+1;
            rejects("CLOCK_OR_FUTURE_UPDATE",()->verify(future.bundle(),0,"",NOW,true));
            same("CLOCK_UNCERTAIN",verify(future.bundle(),0,"",NOW,false).freshness(NOW));
            rejects("CLOCK",()->verify(valid,0,"",0,true));
        });
        scenario("republication does not make stale source retrieval current",()->{
            Fixture stale=new Fixture();stale.retrieved=NOW-31*DAY;
            rejects("DATA_STALE",()->verify(stale.bundle(),0,"",NOW,true));
        });
        scenario("source dates cannot be later than the signed publication",()->{
            Fixture future=new Fixture();future.retrieved=NOW+DAY;
            rejects("SOURCE_DATE_AFTER_PUBLICATION",()->verify(future.bundle(),0,"",NOW,true));
        });
        scenario("manifest validity cannot exceed thirty days or be empty",()->{
            Fixture bad=new Fixture();bad.duration=30*DAY+1;
            rejects("INTEGER_RANGE_expiresAtEpochMillis",()->verify(bad.bundle(),0,"",NOW,true));
            Fixture empty=new Fixture();empty.duration=0;
            rejects("INTEGER_RANGE_expiresAtEpochMillis",()->verify(empty.bundle(),0,"",NOW,true));
        });
        scenario("sequence must be a positive bounded exact integer",()->{
            for(Object value:new Object[]{0,-1,1.5,"1",1_000_000_001L}) {
                Fixture bad=new Fixture();bad.sequenceOverride=value;
                rejects("INTEGER",()->verify(bad.bundle(),0,"",NOW,true));
            }
        });
        scenario("unsupported manifest schema and extra command field are rejected",()->{
            Fixture bad=new Fixture();bad.extraEnvelope="command";
            rejects("UNSUPPORTED_MANIFEST_FIELDS",()->verify(bad.bundle(),0,"",NOW,true));
            Fixture executable=new Fixture();executable.schema="executable-rules-v1";
            rejects("SCHEMA_UNSUPPORTED",()->verify(executable.bundle(),0,"",NOW,true));
        });
        scenario("even correctly signed duplicate JSON keys are rejected",()->{
            Fixture bad=new Fixture();bad.rawManifest="{\"schema\":\"x\",\"schema\":\"y\"}".getBytes(StandardCharsets.UTF_8);
            rejects("중복",()->verify(bad.bundle(),0,"",NOW,true));
        });
        scenario("malformed UTF-8 or oversized signed manifest is rejected before parsing",()->{
            Fixture bad=new Fixture();bad.rawManifest=new byte[]{(byte)0xc0,(byte)0x80};
            rejects("UTF-8",()->verify(bad.bundle(),0,"",NOW,true));
            Fixture large=new Fixture();large.rawManifest=new byte[CatalogUpdateVerifier.MAX_MANIFEST_BYTES+1];
            rejects("SIZE_LIMIT",()->verify(large.bundle(),0,"",NOW,true));
        });
        scenario("unsigned payload changes cannot match the authenticated per-file digest",()->{
            Fixture bad=new Fixture();bad.damageFile=FILES[1];rejects("DIGEST_OR_SIZE",()->verify(bad.bundle(),0,"",NOW,true));
        });
        scenario("signed file size limits checked before consuming member payload",()->{
            Fixture bad=new Fixture();bad.declaredMetadataSize=CatalogUpdateVerifier.MAX_METADATA_BYTES+1;
            rejects("INTEGER_RANGE_sizeBytes",()->verify(bad.bundle(),0,"",NOW,true));
        });
        scenario("catalog descriptor and index cannot disagree with actual files",()->{
            Fixture bad=new Fixture();bad.metadataMutation="descriptor";
            rejects("DESCRIPTOR_MISMATCH",()->verify(bad.bundle(),0,"",NOW,true));
            Fixture index=new Fixture();index.metadataMutation="index";
            rejects("INDEX_MISMATCH",()->verify(index.bundle(),0,"",NOW,true));
            Fixture hash=new Fixture();hash.metadataMutation="digest";
            rejects("CATALOG_DIGEST",()->verify(hash.bundle(),0,"",NOW,true));
        });
        scenario("signed entry-count lies cannot activate a partial database",()->{
            Fixture bad=new Fixture();bad.metadataMutation="count";
            rejects("COUNT_MISMATCH",()->verify(bad.bundle(),0,"",NOW,true));
        });
        scenario("unknown source or misplaced allowlist cannot change source-specific suppression",()->{
            Fixture bad=new Fixture();bad.badSource=true;
            rejects("INVALID_NAME_OR_SOURCE",()->verify(bad.bundle(),0,"",NOW,true));
            Fixture allow=new Fixture();allow.metadataMutation="allow-source";
            rejects("SOURCE_MISMATCH",()->verify(allow.bundle(),0,"",NOW,true));
        });
        scenario("empty dataset is not a successful no-match update",()->{
            Fixture bad=new Fixture();bad.emptyDataset=true;rejectsAny(()->verify(bad.bundle(),0,"",NOW,true));
        });
        scenario("license/provenance metadata must remain present",()->{
            Fixture bad=new Fixture();bad.metadataMutation="provenance";
            rejects("PROVENANCE_MISSING",()->verify(bad.bundle(),0,"",NOW,true));
            Fixture license=new Fixture();license.metadataMutation="license";
            rejects("LICENSE_MISSING",()->verify(license.bundle(),0,"",NOW,true));
        });
        scenario("snapshot date uses a real calendar date",()->{
            Fixture bad=new Fixture();bad.metadataMutation="date";
            rejects("SNAPSHOT_DATE_INVALID",()->verify(bad.bundle(),0,"",NOW,true));
        });
        scenario("missing/extra members and directory/path traversal names are rejected",()->{
            for(String mutation:new String[]{"extra","missing","path","directory"}) {
                Fixture bad=new Fixture();bad.zipMutation=mutation;rejects("ZIP",()->verify(bad.bundle(),0,"",NOW,true));
            }
        });
        scenario("ZIP structural central/local mismatch or overlap cannot be hidden by signed members",()->{
            int central=(int)u32(valid,valid.length-22+16);
            byte[] altered=valid.clone();altered[central+46]^=1;
            rejects("ZIP_NAME",()->verify(altered,0,"",NOW,true));
            byte[] overlap=valid.clone();overlap[central+42]=1;
            rejects("ZIP_DIRECTORY_UNSUPPORTED",()->verify(overlap,0,"",NOW,true));
        });
        scenario("ZIP truncation, concatenation, comments and oversized containers rejected",()->{
            rejects("ZIP",()->verify(Arrays.copyOf(valid,valid.length-1),0,"",NOW,true));
            rejects("ZIP",()->verify(Arrays.copyOf(valid,valid.length+1),0,"",NOW,true));
            rejects("BUNDLE_SIZE",()->verify(new byte[CatalogUpdateVerifier.MAX_BUNDLE_BYTES+1],0,"",NOW,true));
            Fixture comment=new Fixture();comment.zipMutation="comment";rejects("ZIP",()->verify(comment.bundle(),0,"",NOW,true));
        });
        scenario("stored ZIP members also validate without data descriptors",()->{
            Fixture stored=new Fixture();stored.stored=true;same(4,verify(stored.bundle(),0,"",NOW,true).entryCount);
        });
        scenario("cancellation stops validation rather than producing a no-match database",()->{
            rejects("CANCELLED",()->CatalogUpdateVerifier.verify(valid,key.getPublic().getEncoded(),0,"",NOW,true,
                    new ApkEvidence.Budget(new AtomicBoolean(true))));
        });
        scenario("bounded stream rejects endless data and stalled reads",()->{
            rejects("SIZE_LIMIT",()->CatalogUpdateVerifier.readBounded(new ByteArrayInputStream(new byte[10]),9,budget()));
            rejects("READ_STALLED",()->CatalogUpdateVerifier.readBounded(new java.io.InputStream(){
                public int read(){return 0;}public int read(byte[] b){return 0;}},9,budget()));
        });

        Path temporary=Files.createTempDirectory("refurbcheck-catalog-store-test-");
        try {
            CatalogUpdateStore store=new CatalogUpdateStore(temporary.toFile(),key.getPublic().getEncoded(),1,ApkEvidence.sha256(valid));
            scenario("fresh store has no downloaded snapshot",()->{CatalogUpdateStore.Stored value=store.read(NOW,budget());yes(value.snapshot==null);same("",value.error);});
            scenario("valid update activates atomically and is readable after recreating store",()->{
                yes(store.install(valid,NOW,budget()).changed);
                same(1L,new CatalogUpdateStore(temporary.toFile(),key.getPublic().getEncoded(),1,ApkEvidence.sha256(valid)).read(NOW,budget()).snapshot.sequence);
                same(ApkEvidence.sha256(valid),ApkEvidence.sha256(Files.readAllBytes(temporary.resolve("active.zip"))));
            });
            scenario("same valid update is no-op",()->no(store.install(valid,NOW,budget()).changed));
            scenario("tampered import preserves previous active snapshot and rollback floor",()->{
                byte[] before=Files.readAllBytes(temporary.resolve("active.zip")),floor=Files.readAllBytes(temporary.resolve("rollback-floor.json"));
                Fixture bad=new Fixture();bad.sequence=2;bad.damageFile=FILES[1];rejectsAny(()->store.install(bad.bundle(),NOW,budget()));
                yes(Arrays.equals(before,Files.readAllBytes(temporary.resolve("active.zip"))));
                yes(Arrays.equals(floor,Files.readAllBytes(temporary.resolve("rollback-floor.json"))));
            });
            Fixture second=new Fixture();second.sequence=2;byte[] secondBytes=second.bundle();
            scenario("new signed version raises retained rollback floor",()->{yes(store.install(secondBytes,NOW,budget()).changed);same(2L,store.read(NOW,budget()).snapshot.sequence);});
            scenario("rollback refused and current version retained",()->{rejects("ROLLBACK",()->store.install(valid,NOW,budget()));same(2L,store.read(NOW,budget()).snapshot.sequence);});
            scenario("expired active data is retained explicitly, not replaced with old bundled references",()->{
                CatalogUpdateStore.Stored value=store.read(NOW+31*DAY,budget());same(2L,value.snapshot.sequence);same("EXPIRED",value.snapshot.freshness(NOW+31*DAY));
                rejects("UPDATE_EXPIRED",()->store.install(secondBytes,NOW+31*DAY,budget()));
            });
            scenario("deleting the active ZIP does not erase the separately retained floor",()->{
                Files.delete(temporary.resolve("active.zip"));CatalogUpdateStore.Stored value=store.read(NOW,budget());
                yes(value.snapshot==null);same("CATALOG_ACTIVE_MISSING_AFTER_UPDATE",value.error);
                rejects("ROLLBACK",()->store.install(valid,NOW,budget()));
                yes(store.install(secondBytes,NOW,budget()).changed);same(2L,store.read(NOW,budget()).snapshot.sequence);
            });
            scenario("corrupt active content is reported and a newer valid update repairs it",()->{
                Files.write(temporary.resolve("active.zip"),new byte[]{1,2,3});CatalogUpdateStore.Stored bad=store.read(NOW,budget());yes(bad.snapshot==null);yes(!bad.error.isEmpty());
                Fixture third=new Fixture();third.sequence=3;yes(store.install(third.bundle(),NOW,budget()).changed);same(3L,store.read(NOW,budget()).snapshot.sequence);
            });
            scenario("crash after active rename but before floor write recovers newer floor",()->{
                Files.write(temporary.resolve("rollback-floor.json"),("{\"schema\":\"refurbcheck-catalog-floor-v1\",\"sequence\":2,\"bundleSha256\":\""+ApkEvidence.sha256(secondBytes)+"\"}").getBytes(StandardCharsets.UTF_8));
                same(3L,store.read(NOW,budget()).snapshot.sequence);
                JSONObject floor=ReportJson.parse(Files.readAllBytes(temporary.resolve("rollback-floor.json")));same(3L,floor.getLong("sequence"));
            });
            scenario("corrupt rollback state does not silently reset protection",()->{
                Files.write(temporary.resolve("rollback-floor.json"),"{}".getBytes(StandardCharsets.UTF_8));
                yes(!store.read(NOW,budget()).error.isEmpty());rejects("ROLLBACK_STATE",()->store.install(valid,NOW,budget()));
            });
        } finally {deleteTree(temporary);}

        if(args.length>0) {
            Path root=Paths.get(args[0]);byte[] production=Files.readAllBytes(root.resolve("data/catalog-updates/catalog-update.zip"));
            byte[] productionKey=Files.readAllBytes(root.resolve("app/src/main/assets/catalog_update_key.der"));
            scenario("published bundle authenticates against pinned key and baked-in floor",()->{
                same(CatalogUpdateConfig.UPDATE_PUBLIC_KEY_SHA256,ApkEvidence.sha256(productionKey));
                CatalogUpdateVerifier.Snapshot value=CatalogUpdateVerifier.verify(production,productionKey,CatalogUpdateConfig.INITIAL_SEQUENCE,
                        CatalogUpdateConfig.INITIAL_BUNDLE_SHA256,System.currentTimeMillis(),true,budget());
                same(MalwareCatalog.ENTRY_COUNT,value.entryCount);same(MalwareCatalog.DATA_SHA256,value.catalogSha256);
                if(value.sequence==CatalogUpdateConfig.INITIAL_SEQUENCE) {
                    same(CatalogUpdateConfig.INITIAL_BUNDLE_SHA256,ApkEvidence.sha256(production));same(15645,value.entryCount);same(996,value.allowEntryCount);
                }
            });
            scenario("bundled fallback uses identical reviewed references without pretending network verification",()->{
                CatalogUpdateVerifier.Snapshot value=CatalogUpdateVerifier.bundled((name,limit)->Files.readAllBytes(root.resolve("app/src/main/assets").resolve(name)),budget());
                no(value.signedUpdate);same(0L,value.sequence);same(MalwareCatalog.DATA_SHA256,value.catalogSha256);
                same("DATA_STALE",value.freshness(NOW+32*DAY));
            });
        }
        System.out.println("Catalog update tests: "+scenarios+" scenarios, "+assertions+" assertions, "+failures+" failures");
        if(failures>0) System.exit(1);
    }

    private static CatalogUpdateVerifier.Snapshot verify(byte[] bytes,long floor,String hash,long now,boolean fresh) throws Exception {
        return CatalogUpdateVerifier.verify(bytes,key.getPublic().getEncoded(),floor,hash,now,fresh,budget());
    }
    private static ApkEvidence.Budget budget() {return new ApkEvidence.Budget(new AtomicBoolean(false),45_000L,32L*1024*1024,System::nanoTime);}
    private static KeyPair key(int size) throws Exception {KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(size);return generator.generateKeyPair();}
    private static long u32(byte[] bytes,int offset) {return (bytes[offset]&255L)|((bytes[offset+1]&255L)<<8)|((bytes[offset+2]&255L)<<16)|((bytes[offset+3]&255L)<<24);}
    private static void deleteTree(Path root) throws IOException {
        try(java.util.stream.Stream<Path> paths=Files.walk(root)) {
            Path[] sorted=paths.sorted(java.util.Comparator.reverseOrder()).toArray(Path[]::new);
            for(Path path:sorted) Files.deleteIfExists(path);
        }
    }
    private static void scenario(String name,Check check) {
        scenarios++;try {check.run();System.out.println("PASS "+name);}catch(Throwable error) {failures++;System.out.println("FAIL "+name+": "+error);error.printStackTrace(System.out);}
    }
    private static void yes(boolean value) {assertions++;if(!value) throw new AssertionError("expected true");}
    private static void no(boolean value) {yes(!value);}
    private static void same(Object expected,Object actual) {assertions++;if(!expected.equals(actual)) throw new AssertionError("expected "+expected+", got "+actual);}
    private static void rejects(String token,Check check) throws Exception {
        assertions++;try {check.run();}catch(IOException expected) {if(expected.toString().contains(token)) return;throw new AssertionError("expected "+token+", got "+expected);}
        throw new AssertionError("expected rejection "+token);
    }
    private static void rejectsAny(Check check) throws Exception {assertions++;try {check.run();}catch(IOException expected) {return;}throw new AssertionError("expected rejection");}

    private static final class Fixture {
        long sequence=1,created=NOW-1000,duration=30*DAY,retrieved=NOW-DAY;
        Object sequenceOverride=null;
        String schema=CatalogUpdateVerifier.SCHEMA,extraEnvelope="",metadataMutation="",zipMutation="",damageFile="";
        int declaredMetadataSize=-1;
        boolean signWithoutContext=false,stored=false,badSource=false,emptyDataset=false;
        byte[] rawManifest,signatureOverride;KeyPair signingKey=key;
        byte[] bundle() throws Exception {
            LinkedHashMap<String,byte[]> data=new LinkedHashMap<>();
            JSONObject meta=new JSONObject().put("schema","refurbcheck-malware-catalog-v1").put("snapshotDate","2026-11-06")
                    .put("retrievedAtEpochMillis",retrieved);
            JSONArray datasets=new JSONArray(),index=new JSONArray(),sources=new JSONArray();JSONObject counts=new JSONObject();
            int total=0;StringBuilder canonical=new StringBuilder("[");
            for(int i=0;i<5;i++) {
                String rowSource=badSource&&i==0?"evil.source":SOURCES[i];
                byte[] bytes=("sha256\t"+ApkEvidence.sha256(("harmless fixture "+i).getBytes(StandardCharsets.UTF_8))+"\t*\tfixture."+i+"\t"+rowSource+"\n").getBytes(StandardCharsets.UTF_8);
                if(emptyDataset&&i==0) bytes=new byte[0];
                data.put(FILES[i+1],bytes);String hash=ApkEvidence.sha256(bytes);int count=bytes.length==0?0:1;
                JSONObject description=new JSONObject().put("asset",FILES[i+1]).put("sha256",hash).put("sizeBytes",bytes.length)
                        .put("entryCount",count).put("sourceIds",new JSONArray().put(SOURCES[i])).put("license",LICENSES[i]);
                if(i<4) {datasets.put(description);counts.put(SOURCES[i],count);total+=count;
                    sources.put(new JSONObject().put("id",SOURCES[i]).put("source","https://example.invalid/fixture/"+i).put("license",LICENSES[i]));}
                else meta.put("clamavSourceOnlyAllowlist",description);
                index.put(new JSONObject().put("asset",FILES[i+1]).put("sha256",hash));
                if(i>0) canonical.append(',');canonical.append("{\"asset\":\"").append(FILES[i+1]).append("\",\"sha256\":\"").append(hash).append("\"}");
            }
            canonical.append(']');
            meta.put("datasets",datasets).put("catalogIndex",index).put("sources",sources).put("countsBySource",counts)
                    .put("catalogDigest",ApkEvidence.sha256(canonical.toString().getBytes(StandardCharsets.US_ASCII))).put("entryCount",total);
            switch(metadataMutation) {
                case "descriptor":datasets.getJSONObject(0).put("sizeBytes",1);break;
                case "index":index.getJSONObject(0).put("asset","other.tsv");break;
                case "digest":meta.put("catalogDigest",ApkEvidence.sha256(new byte[0]));break;
                case "count":datasets.getJSONObject(0).put("entryCount",2);break;
                case "allow-source":meta.getJSONObject("clamavSourceOnlyAllowlist").put("sourceIds",new JSONArray().put("mvt.android"));break;
                case "provenance":meta.remove("sources");break;
                case "license":datasets.getJSONObject(0).put("license","");break;
                case "date":meta.put("snapshotDate","2026-02-31");break;
            }
            data.put(FILES[0],meta.toString().getBytes(StandardCharsets.UTF_8));
            JSONArray members=new JSONArray();
            for(String name:FILES) {
                byte[] payload=data.get(name);
                members.put(new JSONObject().put("name",name).put("sha256",ApkEvidence.sha256(payload))
                        .put("sizeBytes",name.equals(FILES[0])&&declaredMetadataSize>=0?declaredMetadataSize:payload.length));
            }
            JSONObject envelope=new JSONObject().put("schema",schema).put("sequence",sequenceOverride==null?sequence:sequenceOverride)
                    .put("createdAtEpochMillis",created).put("expiresAtEpochMillis",created+duration).put("files",members);
            if(!extraEnvelope.isEmpty()) envelope.put(extraEnvelope,"must never execute");
            byte[] manifest=rawManifest==null?envelope.toString().getBytes(StandardCharsets.UTF_8):rawManifest;
            Signature signer=Signature.getInstance("SHA256withRSA");signer.initSign(signingKey.getPrivate());
            if(!signWithoutContext) signer.update(CatalogUpdateVerifier.SIGNATURE_CONTEXT);signer.update(manifest);
            byte[] signature=signatureOverride==null?signer.sign():signatureOverride;
            LinkedHashMap<String,byte[]> zipMembers=new LinkedHashMap<>();zipMembers.put("manifest.json",manifest);zipMembers.put("manifest.sig",signature);
            for(String name:FILES) {
                if(zipMutation.equals("missing")&&name.equals(FILES[5])) continue;
                String zipName=zipMutation.equals("path")&&name.equals(FILES[1])?"../malware_clamav.tsv":
                        zipMutation.equals("directory")&&name.equals(FILES[1])?"malware_clamav.tsv/":name;
                byte[] payload=data.get(name).clone();if(name.equals(damageFile)) payload[0]^=1;
                zipMembers.put(zipName,payload);
            }
            if(zipMutation.equals("extra")) zipMembers.put("run.sh","never execute".getBytes(StandardCharsets.UTF_8));
            ByteArrayOutputStream output=new ByteArrayOutputStream();
            try(ZipOutputStream zip=new ZipOutputStream(output,StandardCharsets.UTF_8)) {
                if(zipMutation.equals("comment")) zip.setComment("not supported");
                for(Map.Entry<String,byte[]> item:zipMembers.entrySet()) {
                    ZipEntry entry=new ZipEntry(item.getKey());entry.setTime(315532800000L);
                    if(stored) {CRC32 crc=new CRC32();crc.update(item.getValue());entry.setMethod(ZipEntry.STORED);entry.setSize(item.getValue().length);entry.setCompressedSize(item.getValue().length);entry.setCrc(crc.getValue());}
                    zip.putNextEntry(entry);zip.write(item.getValue());zip.closeEntry();
                }
            }
            return output.toByteArray();
        }
    }
}
