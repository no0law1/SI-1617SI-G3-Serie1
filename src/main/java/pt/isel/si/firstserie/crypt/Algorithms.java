package pt.isel.si.firstserie.crypt;

/**
 * JCA cipher algorithms helper
 */
public class Algorithms {

    public static final String AES_CBC_NOPADDING = "AES/CBC/NoPadding"; // 128
    public static final String AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding"; // 128
    public static final String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
    public static final String RSA_ECB_PKCS1PADDING = "RSA/ECB/PKCS1Padding"; // 1024, 2048
    public static final String RSA_ECB_OAEPWithSHA1ANDMGF1PADDING = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"; // 1024, 2048
    public static final String RSA_ECB_OAEPWithSHA256AndMGF1Padding = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"; // 1024, 2048

    /*
    DES/CBC/NoPadding (56)
    DES/CBC/PKCS5Padding (56)
    DES/ECB/NoPadding (56)
    DES/ECB/PKCS5Padding (56)
    DESede/CBC/NoPadding (168)
    DESede/CBC/PKCS5Padding (168)
    DESede/ECB/NoPadding (168)
    DESede/ECB/PKCS5Padding (168)
    */
}
