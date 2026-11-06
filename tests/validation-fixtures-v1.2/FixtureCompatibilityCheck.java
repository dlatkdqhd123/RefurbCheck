package io.github.refurbcheck;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;

/** Host-only compatibility check for the two benign signed fixture archives. */
public final class FixtureCompatibilityCheck {
    public static void main(String[] args) throws Exception {
        Path root=Paths.get(args[0]);
        byte[] reference=Files.readAllBytes(root.resolve("synthetic-only.tsv"));
        MalwareEvidence.Database db=MalwareEvidence.parseDatabase(reference,
                ApkEvidence.sha256(reference),Collections.singleton("fixture.synthetic"));
        for(String kind:new String[]{"whole","entry"}) {
            final byte[] file=Files.readAllBytes(root.resolve(kind+"-fixture.apk"));
            ApkEvidence.Budget budget=new ApkEvidence.Budget(null);
            MalwareEvidence.Hashes hashes=MalwareEvidence.hash(new ByteArrayInputStream(file),file.length,budget);
            int whole=db.match(hashes).size();
            MalwareEvidence.ZipResult zip=MalwareEvidence.scanZip(new MalwareEvidence.RandomSource() {
                @Override public long length() {return file.length;}
                @Override public int read(long offset,byte[] out,int start,int count) {
                    int actual=Math.min(count,file.length-(int)offset);
                    if(actual<=0)return -1;
                    System.arraycopy(file,(int)offset,out,start,actual);return actual;
                }
            },db,new MalwareEvidence.ZipBudget(budget));
            boolean ok=zip.complete&&("whole".equals(kind)?whole==1&&zip.matchCount==0:whole==0&&zip.matchCount==1);
            System.out.println(kind+": whole="+whole+" entry="+zip.matchCount+" complete="+zip.complete+" issues="+zip.issues);
            if(!ok)throw new AssertionError("Fixture incompatible: "+kind);
            if("entry".equals(kind)&&!"assets/harmless-fixture.txt".equals(zip.matches.get(0).entryName))
                throw new AssertionError("Unexpected matching entry");
        }
    }
}
