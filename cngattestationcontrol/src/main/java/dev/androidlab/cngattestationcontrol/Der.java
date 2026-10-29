package dev.androidlab.cngattestationcontrol;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

final class Der {
    final int tagClass;
    final int tag;
    final byte[] value;

    private Der(int tagClass, int tag, byte[] value) {
        this.tagClass = tagClass;
        this.tag = tag;
        this.value = value;
    }

    static Der one(byte[] bytes) {
        List<Der> nodes = parse(bytes);
        if (nodes.size() != 1) throw new IllegalArgumentException("Expected one DER value");
        return nodes.get(0);
    }

    List<Der> children() { return parse(value); }
    int integer() {
        BigInteger number = new BigInteger(value);
        if (number.bitLength() > 31) throw new IllegalArgumentException("DER integer exceeds int range");
        return number.intValue();
    }

    private static List<Der> parse(byte[] bytes) {
        List<Der> nodes = new ArrayList<>();
        int offset = 0;
        while (offset < bytes.length) {
            int first = bytes[offset++] & 255;
            int tag = first & 31;
            if (tag == 31) {
                tag = 0;
                int item;
                do {
                    if (offset >= bytes.length || tag > (Integer.MAX_VALUE >> 7)) throw new IllegalArgumentException("Invalid DER tag");
                    item = bytes[offset++] & 255;
                    tag = (tag << 7) | (item & 127);
                } while ((item & 128) != 0);
            }
            if (offset >= bytes.length) throw new IllegalArgumentException("Missing DER length");
            int length = bytes[offset++] & 255;
            if ((length & 128) != 0) {
                int count = length & 127;
                if (count == 0 || count > 4 || count > bytes.length - offset) throw new IllegalArgumentException("Invalid DER length");
                long expanded = 0;
                for (int index = 0; index < count; index++) expanded = (expanded << 8) | (bytes[offset++] & 255);
                if (expanded > bytes.length - offset) throw new IllegalArgumentException("Truncated DER value");
                length = (int) expanded;
            }
            if (length > bytes.length - offset) throw new IllegalArgumentException("Truncated DER value");
            nodes.add(new Der(first >> 6, tag, Arrays.copyOfRange(bytes, offset, offset + length)));
            offset += length;
        }
        return nodes;
    }
}
