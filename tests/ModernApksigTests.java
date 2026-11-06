package io.github.refurbcheck;

import com.android.apksig.ApkVerifier;
import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Collections;

/** Upstream benign APK fixtures, not malware detection-rate tests. */
public final class ModernApksigTests {
    private static int checks;
    private static File directory;
    public static void main(String[] args) throws Exception {
        directory=new File(args[0]);
        for(int api:new int[]{26,28,32,33,34,35,36}) {
            expect("v1v2v3-with-rsa-2048-lineage-3-signers.apk",api,true);
            expect("v2-only-with-ecdsa-sha256-p256.apk",api,true);
            expect("v2-only-with-ecdsa-sha256-p256-digest-mismatch.apk",api,false);
            if(api>=28) {
                expect("v31-rsa-2048_2-tgt-33-1-tgt-28.apk",api,true);
                // The upstream future-targeted fixture exposes a model range
                // ambiguity on API33; RefurbCheck must abstain for that error.
                expect("v31-rsa-2048_2-tgt-34-1-tgt-28.apk",api,api!=33);
                expect("v31-tgt-34-v3-attr-value-33.apk",api,api<33);
                expect("v31-block-stripped-v3-attr-value-33.apk",api,api<33);
            }
        }
        String before=signer("v31-rsa-2048_2-tgt-34-1-tgt-28.apk",32);
        String after=signer("v31-rsa-2048_2-tgt-34-1-tgt-28.apk",34);
        require(!before.equals(after),"API34 rotation must change selected signer");
        require(after.equals(signer("v31-rsa-2048_2-tgt-34-1-tgt-28.apk",36)),"API36 selects rotated signer");
        require("VERIFIED".equals(ApkEvidence.signatureStatus(true,Collections.emptyList(),36)),"API36 supported");
        require("UNKNOWN_PLATFORM".equals(ApkEvidence.signatureStatus(true,Collections.emptyList(),37)),"Future platform unknown");
        require("UNKNOWN_SDK_RANGE".equals(ApkEvidence.signatureStatus(false,
                Collections.singletonList("V3_MISSING_SDK_VERSIONS"),33)),"SDK range is not a tamper verdict");
        System.out.println("ModernApksigTests: "+checks+" assertions passed; API26/28/32/33/34/35/36, rotation, tamper, stripping.");
    }
    private static ApkVerifier.Result verify(String name,int api) throws Exception {
        return new ApkVerifier.Builder(new File(directory,name)).setMinCheckedPlatformVersion(api)
                .setMaxCheckedPlatformVersion(api).build().verify();
    }
    private static void expect(String name,int api,boolean valid) throws Exception {
        ApkVerifier.Result result=verify(name,api);
        require(result.isVerified()==valid,name+" API"+api+" expected "+valid+" errors="+result.getAllErrors());
    }
    private static String signer(String name,int api) throws Exception {
        ApkVerifier.Result result=verify(name,api);
        require(result.isVerified()&&result.getSignerCertificates().size()==1,"One verified selected signer at "+api);
        X509Certificate cert=result.getSignerCertificates().get(0);return ApkEvidence.sha256(cert.getEncoded());
    }
    private static void require(boolean condition,String label) {
        checks++;if(!condition) throw new AssertionError(label);
    }
}
