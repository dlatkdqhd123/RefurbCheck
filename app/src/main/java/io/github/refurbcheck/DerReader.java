package io.github.refurbcheck;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Small strict DER reader for the fixed Android attestation schema, not a general ASN.1 library. */
public final class DerReader {
    public static final int MAX_BYTES = 65536;
    private final byte[] data;
    private int position;
    private final int end;

    public DerReader(byte[] data) throws IOException {
        if (data == null || data.length > MAX_BYTES) throw new IOException("DER size limit");
        this.data = data;
        this.position = 0;
        this.end = data.length;
    }

    private DerReader(byte[] data, int start, int end) {
        this.data = data;
        this.position = start;
        this.end = end;
    }

    public boolean hasRemaining() { return position < end; }

    public static Value single(byte[] data) throws IOException {
        DerReader r = new DerReader(data);
        Value result = r.read();
        if (r.hasRemaining()) throw new IOException("Trailing DER data");
        return result;
    }

    private int next() throws IOException {
        if (position >= end) throw new IOException("Truncated DER");
        return data[position++] & 0xff;
    }

    public Value read() throws IOException {
        int encodedStart = position;
        int first = next();
        int tagClass = (first >>> 6) & 3;
        boolean constructed = (first & 0x20) != 0;
        int tag = first & 0x1f;
        if (tag == 0x1f) {
            tag = 0;
            int groups = 0;
            int b;
            do {
                b = next();
                if (++groups > 4 || (groups == 1 && (b & 0x7f) == 0))
                    throw new IOException("Invalid DER high tag");
                tag = (tag << 7) | (b & 0x7f);
            } while ((b & 0x80) != 0);
            if (tag < 31) throw new IOException("Non-minimal DER tag");
        }
        int length = next();
        if ((length & 0x80) != 0) {
            int bytes = length & 0x7f;
            if (bytes == 0 || bytes > 3) throw new IOException("Unsupported DER length");
            length = 0;
            for (int i = 0; i < bytes; i++) {
                int b = next();
                if (i == 0 && b == 0) throw new IOException("Non-minimal DER length");
                length = (length << 8) | b;
            }
            if (length < 128) throw new IOException("Non-minimal DER length");
        }
        if (length > MAX_BYTES || length > end - position) throw new IOException("Truncated DER value");
        if (tagClass == 0 && tag == 0) throw new IOException("Unexpected DER end marker");
        Value value = new Value(data, encodedStart, position, position + length, tagClass, tag, constructed);
        position += length;
        return value;
    }

    public static final class Value {
        private final byte[] data;
        private final int encodedStart, start, end;
        public final int tagClass, tag;
        public final boolean constructed;
        private Value(byte[] data, int encodedStart, int start, int end, int tagClass, int tag, boolean constructed) {
            this.data = data; this.encodedStart = encodedStart; this.start = start; this.end = end;
            this.tagClass = tagClass; this.tag = tag; this.constructed = constructed;
        }
        public void require(int expectedClass, int expectedTag, boolean expectedConstructed) throws IOException {
            if (tagClass != expectedClass || tag != expectedTag || constructed != expectedConstructed)
                throw new IOException("Unexpected DER tag " + tagClass + ":" + tag);
        }
        public List<Value> children() throws IOException {
            if (!constructed) throw new IOException("DER value is not constructed");
            List<Value> values = new ArrayList<>();
            DerReader reader = new DerReader(data, start, end);
            while (reader.hasRemaining()) {
                if (values.size() >= 256) throw new IOException("Too many DER children");
                values.add(reader.read());
            }
            return values;
        }
        public Value explicit() throws IOException {
            if (tagClass != 2 || !constructed) throw new IOException("Expected explicit context tag");
            List<Value> values = children();
            if (values.size() != 1) throw new IOException("Ambiguous explicit DER value");
            return values.get(0);
        }
        public byte[] octets() throws IOException {
            require(0, 4, false);
            return Arrays.copyOfRange(data, start, end);
        }
        /** Complete TLV, used to verify the canonical DER ordering of SET OF members. */
        public byte[] encoded() { return Arrays.copyOfRange(data, encodedStart, end); }
        public boolean bool() throws IOException {
            require(0, 1, false);
            if (end - start != 1 || (data[start] != 0 && data[start] != (byte) 0xff))
                throw new IOException("Invalid DER boolean");
            return data[start] != 0;
        }
        public long unsigned(int expectedTag) throws IOException {
            require(0, expectedTag, false);
            int length = end - start;
            if (length < 1 || length > 8 || (data[start] & 0x80) != 0)
                throw new IOException("Out of range DER integer");
            if (length > 1 && data[start] == 0 && (data[start + 1] & 0x80) == 0)
                throw new IOException("Non-minimal DER integer");
            long value = 0;
            for (int i = start; i < end; i++) value = (value << 8) | (data[i] & 0xffL);
            return value;
        }
    }
}
