package io.github.refurbcheck;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Verifies a data-only, independently signed reference-catalog snapshot.
 * No member is extracted, loaded as code, or interpreted as a remediation command.
 * A valid signature identifies the publisher; it does not establish detection accuracy.
 */
public final class CatalogUpdateVerifier {
    public static final int MAX_BUNDLE_BYTES=8*1024*1024;
    public static final int MAX_INFLATED_BYTES=16*1024*1024;
    public static final int MAX_METADATA_BYTES=1024*1024;
    public static final int MAX_MANIFEST_BYTES=16*1024;
    public static final long MAX_LIFETIME_MILLIS=30L*24*60*60*1000;
    public static final long CLOCK_SKEW_MILLIS=5L*60*1000;
    public static final String SCHEMA="refurbcheck-catalog-update-v1";
    public static final byte[] SIGNATURE_CONTEXT="RefurbCheck catalog update v1\u0000".getBytes(StandardCharsets.US_ASCII);
    public static final String[] DATA_FILES={"malware_clamav.tsv","malware_eset.tsv","malware_echap.tsv","malware_mvt.tsv"};
    public static final String ALLOW_FILE="malware_clamav_allow.tsv",METADATA_FILE="malware_catalog.json";
    private static final String[] SOURCES={"clamav.android","eset.android","echap.stalkerware","mvt.android"};
    private static final String[] ALL_FILES={METADATA_FILE,DATA_FILES[0],DATA_FILES[1],DATA_FILES[2],DATA_FILES[3],ALLOW_FILE};
    private CatalogUpdateVerifier() { }

    public interface Assets { byte[] read(String name,int limit) throws IOException; }

    /** The parsed database is immutable. Metadata is returned as a fresh object. */
    public static final class Snapshot {
        public final MalwareEvidence.Database database;
        public final long sequence,createdAtEpochMillis,expiresAtEpochMillis,retrievedAtEpochMillis;
        public final String bundleSha256,catalogSha256,metadataSha256,snapshotDate;
        public final boolean signedUpdate;
        public final int entryCount,allowEntryCount;
        private final byte[] metadataBytes;
        private Snapshot(MalwareEvidence.Database database,byte[] metadata,JSONObject catalog,long sequence,
                long created,long expires,String bundleSha256,int allowEntryCount,boolean signed) throws IOException {
            this.database=database;this.metadataBytes=metadata.clone();this.sequence=sequence;
            createdAtEpochMillis=created;expiresAtEpochMillis=expires;this.bundleSha256=bundleSha256;
            catalogSha256=database.fileSha256;metadataSha256=ApkEvidence.sha256(metadata);
            snapshotDate=string(catalog,"snapshotDate");retrievedAtEpochMillis=integer(catalog,"retrievedAtEpochMillis",1,Long.MAX_VALUE);
            entryCount=database.entryCount;this.allowEntryCount=allowEntryCount;signedUpdate=signed;
        }
        public JSONObject metadata() throws IOException { return ReportJson.parse(metadataBytes); }
        /** The device clock is not independently authenticated. */
        public String freshness(long now) {
            if(now<=0||now<createdAtEpochMillis-CLOCK_SKEW_MILLIS||now<retrievedAtEpochMillis-CLOCK_SKEW_MILLIS)
                return "CLOCK_UNCERTAIN";
            if(signedUpdate&&now>=expiresAtEpochMillis) return "EXPIRED";
            if(now-retrievedAtEpochMillis>MAX_LIFETIME_MILLIS) return "DATA_STALE";
            return "CURRENT";
        }
    }

    /**
     * requireFresh must be true for every external import/download. False is only
     * for re-reading the previously accepted private snapshot, whose expiry is
     * reported and prevents automatic remediation instead of reviving older IOCs.
     */
    public static Snapshot verify(byte[] bundle,byte[] publicKeyDer,long acceptedSequence,
            String acceptedBundleSha256,long now,boolean requireFresh,ApkEvidence.Budget budget) throws IOException {
        if(bundle==null||bundle.length<22||bundle.length>MAX_BUNDLE_BYTES) throw fail("BUNDLE_SIZE");
        if(acceptedSequence<0||acceptedSequence>1_000_000_000L) throw fail("LOCAL_SEQUENCE_INVALID");
        if(acceptedBundleSha256==null||(!acceptedBundleSha256.isEmpty()&&!ApkEvidence.validSha256(acceptedBundleSha256)))
            throw fail("LOCAL_DIGEST_INVALID");
        if(budget==null) throw new IllegalArgumentException("budget required");
        auditContainer(bundle);
        String bundleHash=ApkEvidence.sha256(bundle);
        budget.check();
        Map<String,byte[]> files=new LinkedHashMap<>();
        long sequence,created,expires;
        try(ZipInputStream zip=new ZipInputStream(new ByteArrayInputStream(bundle),StandardCharsets.UTF_8)) {
            byte[] manifest=entry(zip,"manifest.json",MAX_MANIFEST_BYTES,budget);
            byte[] signature=entry(zip,"manifest.sig",512,budget);
            verifySignature(manifest,signature,publicKeyDer);
            JSONObject envelope=ReportJson.parse(manifest);
            exactKeys(envelope,"schema","sequence","createdAtEpochMillis","expiresAtEpochMillis","files");
            if(!SCHEMA.equals(string(envelope,"schema"))) throw fail("SCHEMA_UNSUPPORTED");
            sequence=integer(envelope,"sequence",1,1_000_000_000L);
            created=integer(envelope,"createdAtEpochMillis",1,Long.MAX_VALUE-MAX_LIFETIME_MILLIS);
            expires=integer(envelope,"expiresAtEpochMillis",created+1,created+MAX_LIFETIME_MILLIS);
            if(sequence<acceptedSequence) throw fail("ROLLBACK_REJECTED");
            if(sequence==acceptedSequence&&!acceptedBundleSha256.isEmpty()&&!bundleHash.equalsIgnoreCase(acceptedBundleSha256))
                throw fail("SEQUENCE_CONFLICT");
            if(requireFresh&&(now<=0||now<created-CLOCK_SKEW_MILLIS)) throw fail("CLOCK_OR_FUTURE_UPDATE");
            if(requireFresh&&now>=expires) throw fail("UPDATE_EXPIRED");
            JSONArray members=envelope.optJSONArray("files");
            if(members==null||members.length()!=ALL_FILES.length) throw fail("FILE_LIST_INVALID");
            int total=0;
            for(int i=0;i<ALL_FILES.length;i++) {
                JSONObject item=members.optJSONObject(i);
                if(item==null) throw fail("FILE_DESCRIPTOR_INVALID");
                exactKeys(item,"name","sizeBytes","sha256");
                String name=string(item,"name"),hash=string(item,"sha256");
                if(!ALL_FILES[i].equals(name)||!hash.matches("[0-9a-f]{64}")) throw fail("FILE_DESCRIPTOR_INVALID");
                int max=METADATA_FILE.equals(name)?MAX_METADATA_BYTES:MAX_INFLATED_BYTES;
                int size=(int)integer(item,"sizeBytes",1,max);
                if(size>MAX_INFLATED_BYTES-total) throw fail("INFLATED_SIZE_LIMIT");
                total+=size;
                byte[] content=entry(zip,name,size,budget);
                if(content.length!=size||!ApkEvidence.sha256(content).equals(hash)) throw fail("FILE_DIGEST_OR_SIZE_MISMATCH");
                files.put(name,content);
            }
            if(zip.getNextEntry()!=null) throw fail("UNEXPECTED_ZIP_MEMBER");
        } catch(IllegalArgumentException error) {throw new IOException("CATALOG_UPDATE_ZIP_OR_KEY_INVALID",error);}
        budget.check();
        Snapshot result=parse(files,sequence,created,expires,bundleHash,true,budget);
        if(requireFresh&&!"CURRENT".equals(result.freshness(now))) throw fail(result.freshness(now));
        return result;
    }

    /** Shipping assets remain digest-pinned; unsigned external catalogs never use this entry point. */
    public static Snapshot bundled(Assets assets,ApkEvidence.Budget budget) throws IOException {
        Map<String,byte[]> files=new LinkedHashMap<>();
        byte[] metadata=assets.read(METADATA_FILE,MAX_METADATA_BYTES);
        if(!ApkEvidence.sha256(metadata).equals(MalwareCatalog.METADATA_SHA256)) throw fail("BUNDLED_METADATA_DIGEST");
        files.put(METADATA_FILE,metadata);
        for(int i=0;i<DATA_FILES.length;i++) {
            if(!DATA_FILES[i].equals(MalwareCatalog.DATA_ASSETS[i])) throw fail("BUNDLED_LAYOUT_MISMATCH");
            byte[] data=assets.read(DATA_FILES[i],MAX_INFLATED_BYTES);
            if(!ApkEvidence.sha256(data).equals(MalwareCatalog.DATA_DIGESTS[i])) throw fail("BUNDLED_DATA_DIGEST");
            files.put(DATA_FILES[i],data);
        }
        byte[] allow=assets.read(ALLOW_FILE,MAX_INFLATED_BYTES);
        if(!ApkEvidence.sha256(allow).equals(MalwareCatalog.ALLOW_SHA256)) throw fail("BUNDLED_ALLOW_DIGEST");
        files.put(ALLOW_FILE,allow);
        JSONObject catalog=ReportJson.parse(metadata);
        long retrieved=integer(catalog,"retrievedAtEpochMillis",1,Long.MAX_VALUE-MAX_LIFETIME_MILLIS);
        Snapshot result=parse(files,0,retrieved,retrieved+MAX_LIFETIME_MILLIS,"",false,budget);
        if(!MalwareCatalog.DATA_SHA256.equals(result.catalogSha256)||result.entryCount!=MalwareCatalog.ENTRY_COUNT
                ||result.allowEntryCount!=MalwareCatalog.ALLOW_ENTRY_COUNT) throw fail("BUNDLED_COUNTS_OR_CATALOG_DIGEST");
        return result;
    }

    private static Snapshot parse(Map<String,byte[]> files,long sequence,long created,long expires,String bundleHash,
            boolean signed,ApkEvidence.Budget budget) throws IOException {
        byte[] metadata=files.get(METADATA_FILE);JSONObject catalog=ReportJson.parse(metadata);
        if(!"refurbcheck-malware-catalog-v1".equals(string(catalog,"schema"))) throw fail("CATALOG_SCHEMA_UNSUPPORTED");
        String date=string(catalog,"snapshotDate");
        if(!date.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}")) throw fail("SNAPSHOT_DATE_INVALID");
        SimpleDateFormat format=new SimpleDateFormat("yyyy-MM-dd",Locale.ROOT);
        format.setLenient(false);format.setTimeZone(TimeZone.getTimeZone("UTC"));
        long snapshot;
        try {Date parsed=format.parse(date);if(parsed==null) throw new ParseException("date",0);snapshot=parsed.getTime();}
        catch(ParseException bad) {throw fail("SNAPSHOT_DATE_INVALID");}
        long retrieved=integer(catalog,"retrievedAtEpochMillis",1,Long.MAX_VALUE-MAX_LIFETIME_MILLIS);
        if(retrieved>created+CLOCK_SKEW_MILLIS||snapshot>created+24L*60*60*1000L) throw fail("SOURCE_DATE_AFTER_PUBLICATION");
        JSONArray datasets=catalog.optJSONArray("datasets"),index=catalog.optJSONArray("catalogIndex");
        if(datasets==null||datasets.length()!=4||index==null||index.length()!=5) throw fail("CATALOG_LAYOUT_INVALID");
        JSONObject allowDescription=catalog.optJSONObject("clamavSourceOnlyAllowlist");
        if(allowDescription==null) throw fail("ALLOWLIST_DESCRIPTION_MISSING");
        List<MalwareEvidence.Database> databases=new ArrayList<>();
        byte[] allowBytes=files.get(ALLOW_FILE);
        int allowCount=descriptor(allowDescription,ALLOW_FILE,"clamav.allow",allowBytes);
        MalwareEvidence.Database allow=MalwareEvidence.parseDatabase(allowBytes,ApkEvidence.sha256(allowBytes),Collections.singleton("clamav.allow"),budget);
        if(allow.entryCount!=allowCount) throw fail("ALLOWLIST_COUNT_MISMATCH");
        StringBuilder canonicalIndex=new StringBuilder("[");int total=0;
        JSONObject counts=catalog.optJSONObject("countsBySource");
        if(counts==null||counts.length()!=4) throw fail("SOURCE_COUNTS_INVALID");
        for(int i=0;i<5;i++) {
            String name=i==4?ALLOW_FILE:DATA_FILES[i];String hash=ApkEvidence.sha256(files.get(name));
            JSONObject indexRow=index.optJSONObject(i);
            if(indexRow==null||!name.equals(string(indexRow,"asset"))||!hash.equals(string(indexRow,"sha256")))
                throw fail("CATALOG_INDEX_MISMATCH");
            if(i>0) canonicalIndex.append(',');
            canonicalIndex.append("{\"asset\":\"").append(name).append("\",\"sha256\":\"").append(hash).append("\"}");
            if(i==4) continue;
            int expectedCount=descriptor(datasets.optJSONObject(i),name,SOURCES[i],files.get(name));
            MalwareEvidence.Database db=MalwareEvidence.parseDatabase(files.get(name),hash,Collections.singleton(SOURCES[i]),budget);
            if(db.entryCount!=expectedCount||integer(counts,SOURCES[i],0,MalwareEvidence.MAX_SIGNATURES)!=db.entryCount)
                throw fail("DATASET_COUNT_MISMATCH");
            total+=db.entryCount;
            databases.add(i==0?db.withSourceAllowlist(allow,Collections.singleton(SOURCES[0])):db);
        }
        canonicalIndex.append(']');
        String digest=ApkEvidence.sha256(canonicalIndex.toString().getBytes(StandardCharsets.US_ASCII));
        if(!digest.equals(string(catalog,"catalogDigest"))||integer(catalog,"entryCount",1,MalwareEvidence.MAX_SIGNATURES)!=total)
            throw fail("CATALOG_DIGEST_OR_COUNT_MISMATCH");
        JSONArray sources=catalog.optJSONArray("sources");
        if(sources==null||sources.length()!=4) throw fail("PROVENANCE_MISSING");
        Set<String> seen=new HashSet<>();
        for(int i=0;i<sources.length();i++) {
            JSONObject source=sources.optJSONObject(i);
            if(source==null) throw fail("PROVENANCE_MISSING");
            String id=string(source,"id"),url=string(source,"source"),license=string(source,"license");
            if(!Arrays.asList(SOURCES).contains(id)||!seen.add(id)||!url.startsWith("https://")||url.length()>2048
                    ||license.isEmpty()||license.length()>128) throw fail("PROVENANCE_INVALID");
        }
        MalwareEvidence.Database db=MalwareEvidence.Database.combine(databases,digest);
        return new Snapshot(db,metadata,catalog,sequence,created,expires,bundleHash,allowCount,signed);
    }

    private static int descriptor(JSONObject description,String name,String source,byte[] bytes) throws IOException {
        if(description==null||bytes==null||!name.equals(string(description,"asset"))
                ||!ApkEvidence.sha256(bytes).equals(string(description,"sha256"))
                ||integer(description,"sizeBytes",1,MAX_INFLATED_BYTES)!=bytes.length) throw fail("DATASET_DESCRIPTOR_MISMATCH");
        JSONArray ids=description.optJSONArray("sourceIds");
        if(ids==null||ids.length()!=1||!source.equals(ids.opt(0))) throw fail("DATASET_SOURCE_MISMATCH");
        String license=string(description,"license");
        if(license.isEmpty()||license.length()>128) throw fail("DATASET_LICENSE_MISSING");
        return (int)integer(description,"entryCount",1,MalwareEvidence.MAX_SIGNATURES);
    }

    private static byte[] entry(ZipInputStream zip,String expected,int maximum,ApkEvidence.Budget budget) throws IOException {
        budget.check();ZipEntry entry=zip.getNextEntry();
        if(entry==null||!expected.equals(entry.getName())||entry.isDirectory()) throw fail("ZIP_MEMBER_ORDER_OR_NAME");
        if(entry.getMethod()!=ZipEntry.DEFLATED&&entry.getMethod()!=ZipEntry.STORED) throw fail("ZIP_METHOD_UNSUPPORTED");
        if(entry.getSize()>maximum) throw fail("ZIP_ENTRY_SIZE_LIMIT");
        byte[] bytes=readBounded(zip,maximum,budget);
        zip.closeEntry();return bytes;
    }

    public static byte[] readBounded(InputStream input,int maximum,ApkEvidence.Budget budget) throws IOException {
        if(input==null||maximum<0) throw new IOException("CATALOG_UPDATE_INPUT_MISSING");
        try(ByteArrayOutputStream output=new ByteArrayOutputStream(Math.min(maximum,8192))) {
            byte[] buffer=new byte[8192];int count,stalls=0;
            while(true) {
                if(budget!=null) budget.check();
                if(Thread.currentThread().isInterrupted()) throw fail("CANCELLED");
                count=input.read(buffer);
                if(count<0) break;
                if(count==0) {if(++stalls>3) throw fail("READ_STALLED");continue;}
                if(count>buffer.length||count>maximum-output.size()) throw fail("SIZE_LIMIT");
                stalls=0;output.write(buffer,0,count);
            }
            return output.toByteArray();
        }
    }

    private static void verifySignature(byte[] manifest,byte[] signature,byte[] encoded) throws IOException {
        try {
            if(encoded==null||encoded.length<256||encoded.length>1024) throw fail("PUBLIC_KEY_INVALID");
            PublicKey key=KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
            if(!(key instanceof RSAPublicKey)||((RSAPublicKey)key).getModulus().bitLength()!=3072||signature.length!=384)
                throw fail("KEY_OR_SIGNATURE_SIZE");
            Signature verifier=Signature.getInstance("SHA256withRSA");verifier.initVerify(key);
            verifier.update(SIGNATURE_CONTEXT);verifier.update(manifest);
            if(!verifier.verify(signature)) throw fail("SIGNATURE_INVALID");
        } catch(GeneralSecurityException invalid) {throw new IOException("CATALOG_UPDATE_SIGNATURE_INVALID",invalid);}
    }

    /**
     * ZipInputStream validates local members/CRCs but ignores the central directory.
     * Require one complete, ordinary ZIP with exactly our eight members so a
     * truncated/polyglot/overlapping or differently named central directory cannot
     * acquire a different meaning in another reader. ZIP64, SFX and comments are
     * intentionally outside this small data-transfer format.
     */
    private static void auditContainer(byte[] bytes) throws IOException {
        String[] names={"manifest.json","manifest.sig",ALL_FILES[0],ALL_FILES[1],ALL_FILES[2],ALL_FILES[3],ALL_FILES[4],ALL_FILES[5]};
        int end=bytes.length-22;
        if(u32(bytes,end)!=0x06054b50L||u16(bytes,end+4)!=0||u16(bytes,end+6)!=0||u16(bytes,end+20)!=0
                ||u16(bytes,end+8)!=names.length||u16(bytes,end+10)!=names.length) throw fail("ZIP_DIRECTORY_INVALID");
        long directorySize=u32(bytes,end+12),directoryStart=u32(bytes,end+16);
        if(directoryStart+directorySize!=end||directoryStart<30||directorySize<46L*names.length)
            throw fail("ZIP_DIRECTORY_RANGE");
        int central=(int)directoryStart,nextLocal=0;
        for(String name:names) {
            if(u32(bytes,central)!=0x02014b50L||u16(bytes,central+6)>20) throw fail("ZIP_DIRECTORY_ENTRY");
            int flags=u16(bytes,central+8),method=u16(bytes,central+10),nameLength=u16(bytes,central+28);
            int extraLength=u16(bytes,central+30),commentLength=u16(bytes,central+32);
            long crc=u32(bytes,central+16),compressed=u32(bytes,central+20),inflated=u32(bytes,central+24),local=u32(bytes,central+42);
            if((flags&~0x0808)!=0||(method!=0&&method!=8)||u16(bytes,central+34)!=0||extraLength>4096||commentLength!=0
                    ||compressed>MAX_BUNDLE_BYTES||inflated>MAX_INFLATED_BYTES||local!=nextLocal)
                throw fail("ZIP_DIRECTORY_UNSUPPORTED");
            requireName(bytes,central+46,nameLength,name);
            if((long)central+46+nameLength+extraLength>end) throw fail("ZIP_DIRECTORY_RANGE");
            rejectZip64Extra(bytes,central+46+nameLength,extraLength);
            if(u32(bytes,nextLocal)!=0x04034b50L||u16(bytes,nextLocal+4)>20||u16(bytes,nextLocal+6)!=flags
                    ||u16(bytes,nextLocal+8)!=method) throw fail("ZIP_LOCAL_HEADER_MISMATCH");
            int localNameLength=u16(bytes,nextLocal+26),localExtra=u16(bytes,nextLocal+28);
            requireName(bytes,nextLocal+30,localNameLength,name);
            if(localExtra>4096) throw fail("ZIP_EXTRA_LIMIT");
            rejectZip64Extra(bytes,nextLocal+30+localNameLength,localExtra);
            long dataStart=(long)nextLocal+30+localNameLength+localExtra,dataEnd=dataStart+compressed;
            if(dataEnd>directoryStart) throw fail("ZIP_LOCAL_RANGE");
            if((flags&8)==0) {
                if(u32(bytes,nextLocal+14)!=crc||u32(bytes,nextLocal+18)!=compressed||u32(bytes,nextLocal+22)!=inflated)
                    throw fail("ZIP_SIZE_OR_CRC_HEADER_MISMATCH");
            } else {
                // Only standard descriptors emitted after bounded DEFLATE data.
                if(method!=8) throw fail("ZIP_DESCRIPTOR_METHOD");
                int descriptor=(int)dataEnd;
                if(u32(bytes,descriptor)==0x08074b50L) descriptor+=4;
                if(u32(bytes,descriptor)!=crc||u32(bytes,descriptor+4)!=compressed||u32(bytes,descriptor+8)!=inflated)
                    throw fail("ZIP_DESCRIPTOR_MISMATCH");
                dataEnd=(long)descriptor+12;
                if(dataEnd>directoryStart) throw fail("ZIP_DESCRIPTOR_RANGE");
            }
            nextLocal=(int)dataEnd;central+=46+nameLength+extraLength;
        }
        if(nextLocal!=directoryStart||central!=end) throw fail("ZIP_TRAILING_OR_OVERLAPPING_DATA");
    }
    private static void requireName(byte[] bytes,int offset,int length,String expected) throws IOException {
        byte[] name=expected.getBytes(StandardCharsets.US_ASCII);
        if(length!=name.length||offset<0||offset>bytes.length-length) throw fail("ZIP_NAME_INVALID");
        for(int i=0;i<length;i++) if(bytes[offset+i]!=name[i]) throw fail("ZIP_NAME_INVALID");
    }
    private static void rejectZip64Extra(byte[] bytes,int start,int length) throws IOException {
        if(start<0||length<0||start>bytes.length-length) throw fail("ZIP_EXTRA_INVALID");
        int cursor=start,end=start+length;
        while(cursor<end) {
            if(end-cursor<4) throw fail("ZIP_EXTRA_INVALID");
            int tag=u16(bytes,cursor),size=u16(bytes,cursor+2);cursor+=4;
            if(tag==1||size>end-cursor) throw fail("ZIP64_OR_EXTRA_INVALID");
            cursor+=size;
        }
    }
    private static int u16(byte[] bytes,int offset) throws IOException {
        if(offset<0||offset>bytes.length-2) throw fail("ZIP_TRUNCATED");
        return (bytes[offset]&255)|((bytes[offset+1]&255)<<8);
    }
    private static long u32(byte[] bytes,int offset) throws IOException {
        return (long)u16(bytes,offset)|((long)u16(bytes,offset+2)<<16);
    }

    static long integer(JSONObject object,String key,long minimum,long maximum) throws IOException {
        Object value=object==null?null:object.opt(key);
        if(!(value instanceof Number)||!value.toString().matches("0|[1-9][0-9]{0,18}")) throw fail("INTEGER_INVALID_"+key);
        try {long result=Long.parseLong(value.toString());if(result<minimum||result>maximum) throw fail("INTEGER_RANGE_"+key);return result;}
        catch(NumberFormatException bad) {throw fail("INTEGER_INVALID_"+key);}
    }
    static String string(JSONObject object,String key) throws IOException {
        Object value=object==null?null:object.opt(key);
        if(!(value instanceof String)) throw fail("STRING_REQUIRED_"+key);
        return (String)value;
    }
    private static void exactKeys(JSONObject object,String... names) throws IOException {
        if(object.length()!=names.length) throw fail("UNSUPPORTED_MANIFEST_FIELDS");
        for(String name:names) if(!object.has(name)) throw fail("MANIFEST_FIELD_MISSING");
    }
    private static IOException fail(String reason) {return new IOException("CATALOG_UPDATE_"+reason);}
}
