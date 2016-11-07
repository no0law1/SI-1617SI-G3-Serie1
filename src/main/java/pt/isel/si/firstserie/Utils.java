package pt.isel.si.firstserie;

import java.util.Base64;

/**
 * Utilities methods
 */
public class Utils {

    public static String base64Encode(byte[] bytes) {
        return Base64.getUrlEncoder().encodeToString(bytes);
    }

    public static String base64DecodeToString(byte[] bytes) {
        byte[] r = Base64.getUrlDecoder().decode(bytes);
        return new String(r);
    }

    public static byte[] base64Decode(byte[] bytes) {
        return Base64.getUrlDecoder().decode(bytes);
    }

    public static byte[] joinArrays(byte[] a, byte[] b) {
        int aLen = a.length;
        int bLen = b.length;
        byte[] c= new byte[aLen+bLen];
        System.arraycopy(a, 0, c, 0, aLen);
        System.arraycopy(b, 0, c, aLen, bLen);
        return c;
    }

}
