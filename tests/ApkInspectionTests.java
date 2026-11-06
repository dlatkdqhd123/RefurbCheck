package io.github.refurbcheck;

import com.android.apksig.ApkVerifier;
import com.android.apksig.util.DataSink;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/** Bounded evidence, cancellation and actual signed/tampered APK fixtures; no malware samples. */
public final class ApkInspectionTests {
    private static int scenarios,assertions,failures;
    private static final byte[] ABC="abc".getBytes(StandardCharsets.UTF_8);
    private static final String ABC_SHA="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    private interface Checked { void run() throws Exception; }
    public static void main(String[] args) throws Exception {
        if(args.length!=3) throw new IllegalArgumentException("assets directory, signed APK, tampered APK required");
        scenario("known SHA-256 vector",()->same(ABC_SHA,ApkEvidence.sha256(ABC)));
        scenario("streaming hash with exact size",()->same(ABC_SHA,ApkEvidence.hash(new ByteArrayInputStream(ABC),3,budget(3))));
        scenario("empty file is a hash, not a signature claim",()->same(ApkEvidence.sha256(new byte[0]),ApkEvidence.hash(new ByteArrayInputStream(new byte[0]),0,budget(0))));
        scenario("truncated file cannot produce a successful hash",()->rejects("TRUNCATED",()->ApkEvidence.hash(new ByteArrayInputStream(ABC),4,budget(100))));
        scenario("growing file cannot produce a successful hash",()->rejects("GREW",()->ApkEvidence.hash(new ByteArrayInputStream(ABC),2,budget(100))));
        scenario("oversized file is rejected before any read",()->rejects("FILE_BYTE_LIMIT",()->ApkEvidence.hash(new ByteArrayInputStream(ABC),ApkEvidence.MAX_FILE_BYTES+1,budget(100))));
        scenario("cancelled scan cannot produce hash",()->rejects("CANCELLED",()->ApkEvidence.hash(new ByteArrayInputStream(ABC),3,new ApkEvidence.Budget(new AtomicBoolean(true)))));
        scenario("midread cancellation is not a hash success",()->{
            AtomicBoolean cancelled=new AtomicBoolean(false); ApkEvidence.Budget b=new ApkEvidence.Budget(cancelled);
            ByteArrayInputStream stream=new ByteArrayInputStream(ABC) {
                @Override public synchronized int read(byte[] bytes,int off,int len) { int n=super.read(bytes,off,len);cancelled.set(true);return n; }
            };
            rejects("CANCELLED",()->ApkEvidence.hash(stream,3,b));
        });
        scenario("clock deadline does not silently pass",()->{
            AtomicLong clock=new AtomicLong(0);ApkEvidence.Budget b=new ApkEvidence.Budget(new AtomicBoolean(false),1,100,clock::get);
            clock.set(1_000_000L);rejects("TIME_LIMIT",b::check);
        });
        scenario("read budget counts actual bytes and prevents complete result",()->{
            ApkEvidence.Budget b=budget(2);rejects("TOTAL_BYTE_LIMIT",()->ApkEvidence.hash(new ByteArrayInputStream(ABC),3,b));same(2L,b.hashBytesRead());
        });
        scenario("negative file size is unknown",()->rejects("UNKNOWN_SIZE",()->ApkEvidence.hash(new ByteArrayInputStream(ABC),-1,budget(100))));
        byte[] bundled=Files.readAllBytes(new File(args[0],"ioc_sha256.txt").toPath());
        scenario("real pinned MIT IOC database is nonempty and exact",()->{
            ApkEvidence.IocIndex index=ApkEvidence.bundledIocs(bundled);same(156,index.entryCount);same(156,index.uniqueHashes());
            String first="";
            for(String line:new String(bundled,StandardCharsets.UTF_8).split("\n"))
                if(!line.startsWith("#")&&!line.trim().isEmpty()) { first=line.split("\t")[0];break; }
            same(Collections.singletonList("btmob"),index.match(first));same(0,index.match(ABC_SHA).size());
            same(0,index.match("bad").size());
        });
        scenario("modified IOC asset fails closed",()->{
            byte[] bad=bundled.clone();bad[bad.length-2]^=1;rejects("IOC_DIGEST_MISMATCH",()->ApkEvidence.bundledIocs(bad));
        });
        scenario("empty IOC list cannot become no match",()->rejects("IOC_EMPTY",()->parse("# nothing\n")));
        scenario("malformed IOC row rejected",()->rejects("IOC_MALFORMED",()->parse("invalid\tbtmob\n")));
        scenario("unknown IOC provenance rejected",()->rejects("IOC_MALFORMED",()->parse(ABC_SHA+"\tunknown\n")));
        scenario("duplicate IOC row rejected",()->rejects("IOC_DUPLICATE",()->parse(ABC_SHA+"\tbtmob\n"+ABC_SHA+"\tbtmob\n")));
        scenario("matching parser is case insensitive",()->same(Collections.singletonList("btmob"),parse(ABC_SHA.toUpperCase(java.util.Locale.ROOT)+"\tbtmob\n").match(ABC_SHA)));
        scenario("file identity changes are detected",()->{
            ApkEvidence.Stamp a=new ApkEvidence.Stamp(3,20,30,1,2,true);
            yes(a.same(new ApkEvidence.Stamp(3,20,30,1,2,true)));
            no(a.same(new ApkEvidence.Stamp(3,20,30,1,3,true)));
            no(a.same(new ApkEvidence.Stamp(4,20,30,1,2,true)));
            no(a.same(new ApkEvidence.Stamp(3,21,30,1,2,true)));
            no(a.same(new ApkEvidence.Stamp(3,20,31,1,2,true)));
            no(a.same(new ApkEvidence.Stamp(3,20,30,1,2,false)));
        });
        scenario("unsupported platform cannot become signature success",()->{
            same("UNKNOWN_PLATFORM",ApkEvidence.signatureStatus(true,Collections.emptyList(),35));
            same("UNKNOWN_PLATFORM",ApkEvidence.signatureStatus(false,Collections.singletonList("V3_SIG_APK_DIGEST_DID_NOT_VERIFY"),35));
        });
        scenario("unsupported crypto never classified as invalid malware",()->same("UNKNOWN_UNSUPPORTED",ApkEvidence.signatureStatus(false,Collections.singletonList("V2_SIG_NO_SUPPORTED_SIGNATURES"),33)));
        scenario("known digest failure classified as invalid within model",()->same("INVALID",ApkEvidence.signatureStatus(false,Collections.singletonList("V2_SIG_APK_DIGEST_DID_NOT_VERIFY"),33)));
        scenario("failure without diagnostic remains unknown",()->same("UNKNOWN_VERIFIER",ApkEvidence.signatureStatus(false,Collections.emptyList(),26)));
        scenario("signer order and case are immaterial but missing evidence is not",()->{
            String other=ApkEvidence.sha256(new byte[]{9});
            yes(ApkEvidence.sameSignerSets(Arrays.asList(ABC_SHA,other),Arrays.asList(other,ABC_SHA.toUpperCase(java.util.Locale.ROOT))));
            no(ApkEvidence.sameSignerSets(Collections.emptyList(),Collections.emptyList()));
            no(ApkEvidence.sameSignerSets(Collections.singletonList("bad"),Collections.singletonList("bad")));
            no(ApkEvidence.sameSignerSets(Collections.singletonList(ABC_SHA),Collections.singletonList(other)));
        });
        scenario("bounded APK source slices reproduce only requested bytes",()->{
            Path path=Files.createTempFile("refurbcheck-source-",".bin");
            try {
                Files.write(path,"0123456789".getBytes(StandardCharsets.UTF_8));
                try(RandomAccessFile file=new RandomAccessFile(path.toFile(),"r")) {
                    ApkEvidence.Budget b=budget(100);ApkInspection.BoundedSource source=new ApkInspection.BoundedSource(file.getChannel(),0,10,b);
                    ByteBuffer got=source.slice(2,5).getByteBuffer(1,3);byte[] bytes=new byte[3];got.get(bytes);same("345",new String(bytes,StandardCharsets.UTF_8));
                    ByteArrayOutputStream out=new ByteArrayOutputStream();
                    source.feed(7,3,new DataSink() {
                        @Override public void consume(byte[] v,int off,int len) {out.write(v,off,len);}
                        @Override public void consume(ByteBuffer v) {byte[] temp=new byte[v.remaining()];v.get(temp);out.write(temp,0,temp.length);}
                    });
                    same("789",new String(out.toByteArray(),StandardCharsets.UTF_8));same(6L,b.signatureBytesRead());
                    boolean rejected=false;try{source.slice(9,2);}catch(IndexOutOfBoundsException e){rejected=true;}yes(rejected);
                }
            } finally {Files.deleteIfExists(path);}
        });
        scenario("actual signed APK verifies using genuine apksig port",()->{
            ApkVerifier.Result result=verify(new File(args[1]),33,budget(100*1024*1024));
            yes(result.isVerified());yes(result.isVerifiedUsingV2Scheme()||result.isVerifiedUsingV3Scheme()||result.isVerifiedUsingV31Scheme());
            yes(!result.getSignerCertificates().isEmpty());
        });
        scenario("byte-tampered real APK fails cryptographic verification",()->{
            ApkVerifier.Result result=verify(new File(args[2]),33,budget(100*1024*1024));
            no(result.isVerified());yes(!result.getAllErrors().isEmpty());
            yes(result.getAllErrors().toString().toLowerCase(java.util.Locale.ROOT).contains("digest"));
        });
        scenario("actual signed APK API26 model verifies",()->yes(verify(new File(args[1]),26,budget(100*1024*1024)).isVerified()));
        scenario("verifier input observes cancellation",()->rejects("CANCELLED",()->verify(new File(args[1]),26,new ApkEvidence.Budget(new AtomicBoolean(true)))));
        scenario("verifier input observes read limit",()->rejects("TOTAL_BYTE_LIMIT",()->verify(new File(args[1]),26,budget(10))));
        System.out.println("APK evidence tests: "+scenarios+" scenarios, "+assertions+" assertions, "+failures+" failures");
        if(failures!=0) throw new AssertionError("APK evidence test failures");
    }
    static ApkVerifier.Result verify(File path,int api,ApkEvidence.Budget budget) throws Exception {
        try(RandomAccessFile file=new RandomAccessFile(path,"r")) {
            return new ApkVerifier.Builder(new ApkInspection.BoundedSource(file.getChannel(),0,file.length(),budget))
                    .setMinCheckedPlatformVersion(api).setMaxCheckedPlatformVersion(api).build().verify();
        }
    }
    private static ApkEvidence.IocIndex parse(String text) throws IOException {
        byte[] bytes=text.getBytes(StandardCharsets.UTF_8);
        return ApkEvidence.parseIocs(bytes,ApkEvidence.sha256(bytes),new HashSet<>(Collections.singletonList("btmob")));
    }
    private static ApkEvidence.Budget budget(long bytes) {return new ApkEvidence.Budget(new AtomicBoolean(false),180000,bytes,System::nanoTime);}
    private static void scenario(String name,Checked code) {
        scenarios++;try{code.run();System.out.println("PASS "+name);}catch(Throwable e){failures++;System.out.println("FAIL "+name+": "+e);e.printStackTrace(System.out);}
    }
    private static void same(Object a,Object b) {assertions++;if(!java.util.Objects.equals(a,b))throw new AssertionError(a+" != "+b);}
    private static void yes(boolean value) {assertions++;if(!value)throw new AssertionError("expected true");}
    private static void no(boolean value) {yes(!value);}
    private static void rejects(String expected,Checked task) throws Exception {
        assertions++;
        try {task.run();} catch(IOException e) {if(String.valueOf(e.getMessage()).contains(expected))return;throw new AssertionError("unexpected error "+e);}
        throw new AssertionError("expected "+expected);
    }
}
