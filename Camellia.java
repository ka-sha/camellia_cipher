import java.io.*;
import java.util.Random;
import java.security.*;

class Camellia {
    private static int[] S1 = {112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65,
            35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189,
            134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26,
            166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77,
            139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153,
            223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215,
            20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34,
            254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80,
            170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210,
            16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148,
            135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226,
            82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46,
            233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89,
            120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250,
            114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164,
            64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158};

    private static int[] S2 = {224, 5, 88, 217, 103, 78, 129, 203, 201, 11, 174, 106, 213, 24, 93, 130,
            70, 223, 214, 39, 138, 50, 75, 66, 219, 28, 158, 156, 58, 202, 37, 123,
            13, 113, 95, 31, 248, 215, 62, 157, 124, 96, 185, 190, 188, 139, 22, 52,
            77, 195, 114, 149, 171, 142, 186, 122, 179, 2, 180, 173, 162, 172, 216, 154,
            23, 26, 53, 204, 247, 153, 97, 90, 232, 36, 86, 64, 225, 99, 9, 51,
            191, 152, 151, 133, 104, 252, 236, 10, 218, 111, 83, 98, 163, 46, 8, 175,
            40, 176, 116, 194, 189, 54, 34, 56, 100, 30, 57, 44, 166, 48, 229, 68,
            253, 136, 159, 101, 135, 107, 244, 35, 72, 16, 209, 81, 192, 249, 210, 160,
            85, 161, 65, 250, 67, 19, 196, 47, 168, 182, 60, 43, 193, 255, 200, 165,
            32, 137, 0, 144, 71, 239, 234, 183, 21, 6, 205, 181, 18, 126, 187, 41,
            15, 184, 7, 4, 155, 148, 33, 102, 230, 206, 237, 231, 59, 254, 127, 197,
            164, 55, 177, 76, 145, 110, 141, 118, 3, 45, 222, 150, 38, 125, 198, 92,
            221, 242, 79, 25, 63, 220, 121, 29, 82, 235, 243, 109, 94, 251, 105, 178,
            240, 49, 12, 212, 207, 140, 226, 117, 169, 74, 87, 132, 17, 69, 27, 245,
            228, 14, 115, 170, 241, 221, 89, 20, 108, 146, 84, 208, 120, 112, 227, 73,
            128, 80, 167, 246, 119, 147, 134, 131, 42, 199, 91, 233, 238, 143, 1, 61};

    private static int[] S3 = {56, 65, 22, 118, 217, 147, 96, 242, 114, 194, 171, 154, 117, 6, 87, 160,
            145, 247, 181, 201, 162, 140, 210, 144, 246, 7, 167, 39, 142, 178, 73, 222,
            67, 92, 215, 199, 62, 245, 143, 103, 31, 24, 110, 175, 47, 226, 133, 13,
            83, 240, 156, 101, 234, 163, 174, 158, 236, 128, 45, 107, 168, 43, 54, 166,
            197, 134, 77, 51, 253, 102, 88, 150, 58, 9, 149, 16, 120, 216, 66, 204,
            239, 38, 229, 97, 26, 63, 59, 130, 182, 219, 212, 152, 232, 139, 2, 235,
            10, 44, 29, 176, 111, 141, 136, 14, 25, 135, 78, 11, 169, 12, 121, 17,
            127, 34, 231, 89, 225, 218, 61, 200, 18, 4, 116, 84, 48, 126, 180, 40,
            85, 104, 80, 190, 208, 196, 49, 203, 42, 173, 15, 202, 112, 255, 50, 105,
            8, 98, 0, 36, 209, 251, 186, 237, 69, 129, 115, 109, 132, 159, 238, 74,
            195, 46, 193, 1, 230, 37, 72, 153, 185, 179, 123, 249, 206, 191, 223, 113,
            41, 205, 108, 19, 100, 155, 99, 157, 192, 75, 183, 165, 137, 95, 177, 23,
            244, 188, 211, 70, 207, 55, 94, 71, 148, 250, 252, 91, 151, 254, 90, 172,
            60, 76, 3, 53, 243, 35, 184, 93, 106, 146, 213, 33, 68, 81, 198, 125,
            57, 131, 220, 170, 124, 119, 86, 5, 27, 164, 21, 52, 30, 28, 248, 82,
            32, 20, 233, 189, 221, 228, 161, 224, 138, 241, 214, 122, 187, 227, 64, 79};

    private static int[] S4 = {112, 44, 179, 192, 228, 87, 234, 174, 35, 107, 69, 165, 237, 79, 29, 146,
            134, 175, 124, 31, 62, 220, 94, 11, 166, 57, 213, 93, 217, 90, 81, 108,
            139, 154, 251, 176, 116, 43, 240, 132, 223, 203, 52, 118, 109, 169, 209, 4,
            20, 58, 222, 17, 50, 156, 83, 242, 254, 207, 195, 122, 36, 232, 96, 105,
            170, 160, 161, 98, 84, 30, 224, 100, 16, 0, 163, 117, 138, 230, 9, 221,
            135, 131, 205, 144, 115, 246, 157, 191, 82, 216, 200, 198, 129, 111, 19, 99,
            233, 167, 159, 188, 41, 249, 47, 180, 120, 6, 231, 113, 212, 171, 136, 141,
            114, 185, 248, 172, 54, 42, 60, 241, 64, 211, 187, 67, 21, 173, 119, 128,
            130, 236, 39, 229, 133, 53, 12, 65, 239, 147, 25, 33, 14, 78, 101, 189,
            184, 143, 235, 206, 48, 95, 197, 26, 225, 202, 71, 61, 1, 214, 86, 77,
            13, 102, 204, 45, 18, 32, 177, 153, 76, 194, 126, 5, 183, 49, 23, 215,
            88, 97, 27, 28, 15, 22, 24, 34, 68, 178, 181, 145, 8, 168, 252, 80,
            208, 125, 137, 151, 91, 149, 255, 210, 196, 72, 247, 219, 3, 218, 63, 148,
            92, 2, 74, 51, 103, 243, 127, 226, 155, 38, 55, 59, 150, 75, 190, 46,
            121, 140, 110, 142, 245, 182, 253, 89, 152, 106, 70, 186, 37, 66, 162, 250,
            7, 85, 238, 10, 73, 104, 56, 164, 40, 123, 201, 193, 227, 244, 199, 158};

    private static byte[] C = {(byte) 0xa0, (byte)0x9e, 0x66, 0x7f, 0x3b, (byte)0xcc, (byte)0x90, (byte)0x8b,
            (byte)0xb6, 0x7a, (byte)0xe8, 0x58, 0x4c, (byte)0xaa, 0x73, (byte)0xb2,
            (byte)0xc6, (byte)0xef, 0x37, 0x2f, (byte)0xe9, 0x4f, (byte)0x82, (byte)0xbe,
            0x54, (byte)0xff, 0x53, (byte)0xa5, (byte)0xf1, (byte)0xd3, 0x6f, 0x1c,
            0x10, (byte)0xe5, 0x27, (byte)0xfa, (byte)0xde, 0x68, 0x2d, 0x1d,
            (byte)0xb0, 0x56, (byte)0x88, (byte)0xc2, (byte)0xb3, (byte)0xe6, (byte)0xc1, (byte)0xfd};

    private static byte[] KL_byte = new byte[16], KR_byte = new byte[16], KA_byte = new byte[16], KB_byte = new byte[16], ExtendedKey;

    private static boolean keyIs128;

    public static void encryptionOrDecryption (String FileName, String password, int keyLen, boolean forEncryption) {
        init(password, keyLen);
        keyExtension();
        byte[] SourceTextBlock = new byte[8];
        FileInputStream SourceText;
        try{
            SourceText = new FileInputStream(FileName);
            FileOutputStream ChangedText;
            byte[] CTR = new byte[16], IV = new byte[8];
            if (forEncryption) {
                new Random().nextBytes(IV);
                System.arraycopy(IV, 0, CTR, 0, 8);
                ChangedText = new FileOutputStream(createPath(FileName, true));
                ChangedText.write(IV, 0, 8);
            } else {
                ChangedText = new FileOutputStream(createPath(FileName, false));
                SourceText.read(IV, 0, 8);
                System.arraycopy(IV, 0, CTR, 0, 8);
            }
            while (SourceText.available() >= 8) {
                byte[] t = new byte[16];
                System.arraycopy(CTR, 0, t, 0, 16);
                eK(CTR);
                SourceText.read(SourceTextBlock, 0, 8);
                for(int i = 0; i < 8; i++)
                    SourceTextBlock[i] = (byte) (SourceTextBlock[i] ^ CTR[i]);
                ChangedText.write(SourceTextBlock, 0, 8);
                add1(t);
                System.arraycopy(t, 0, CTR, 0, 16);
            }
            if (SourceText.available() != 0) {
                eK(CTR);
                int available = SourceText.available();
                SourceText.read(SourceTextBlock, 0, available);
                for (int i = 0; i < available; i++)
                    SourceTextBlock[i] = (byte) (SourceTextBlock[i] ^ CTR[i]);
                ChangedText.write(SourceTextBlock, 0, available);
            }
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
    }

    private static void init (String password, int keyLen) {
        byte[] key;
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-256");
            key = sha1.digest(password.getBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        switch (keyLen) {
            case 1:
                keyIs128 = true;
                System.arraycopy(key, 0, KL_byte, 0, 16);
                break;
            case 2:
                System.arraycopy(key, 0, KL_byte, 0, 16);
                byte[] ForKR = new byte[8];
                System.arraycopy(key, 16, ForKR, 0, 8);
                System.arraycopy(ForKR, 0, KR_byte, 0, 8);
                for (int i = 0; i < 8; i++)
                    ForKR[i] = (byte)(~ForKR[i]);
                System.arraycopy(ForKR, 0, KR_byte, 8, 8);
                break;
            case 3:
                System.arraycopy(key, 0, KL_byte, 0, 16);
                System.arraycopy(key, 16, KR_byte, 0, 16);
                break;
            default:
                throw new IllegalArgumentException("Неправильный размер ключа.");
        }
    }

    private static void keyExtension () {
        if (keyIs128) {
            ExtendedKey = new byte[208];
            System.arraycopy(KL_byte, 0, KA_byte, 0, 16);
            roundsWithF(KA_byte, C, 0, 2);
            for (int i = 0; i < 16; i++)
                KA_byte[i] = (byte) (KL_byte[i] ^ KA_byte[i]);
            roundsWithF(KA_byte, C, 2, 2);
            System.arraycopy(KL_byte, 0, ExtendedKey, 0, 16);//kwi
            System.arraycopy(KA_byte, 0, ExtendedKey, 16, 16);//k1k2
            boolean[] KA_boolean = byteArray2BooleanArray(KA_byte);
            boolean[] KL_boolean = byteArray2BooleanArray(KL_byte);
            moveLeft(KL_boolean, 15);
            System.arraycopy(booleanArray2ByteArray(KL_boolean), 0, ExtendedKey, 32, 16);//k3k4
            moveLeft(KA_boolean, 15);
            System.arraycopy(booleanArray2ByteArray(KA_boolean), 0, ExtendedKey, 48, 16);//k5k6
            moveLeft(KA_boolean, 15);
            System.arraycopy(booleanArray2ByteArray(KA_boolean), 0, ExtendedKey, 64, 16);//k1xk2x
            moveLeft(KL_boolean, 30);
            System.arraycopy(booleanArray2ByteArray(KL_boolean), 0, ExtendedKey, 80, 16);//k7k8
            moveLeft(KA_boolean, 15);
            System.arraycopy(booleanArray2ByteArray(KA_boolean), 0, ExtendedKey, 96, 8);//k9
            moveLeft(KL_boolean, 15);
            System.arraycopy(booleanArray2ByteArray(KL_boolean), 8, ExtendedKey, 104, 8);//k10
            moveLeft(KA_boolean, 15);
            System.arraycopy(booleanArray2ByteArray(KA_boolean), 0, ExtendedKey, 112, 16);//k11k12
            moveLeft(KL_boolean, 17);
            System.arraycopy(booleanArray2ByteArray(KL_boolean), 0, ExtendedKey, 128, 16);//k3xk4x
            moveLeft(KL_boolean, 17);
            System.arraycopy(booleanArray2ByteArray(KL_boolean), 0, ExtendedKey, 144, 16);//k13k14
            moveLeft(KA_boolean, 34);
            System.arraycopy(booleanArray2ByteArray(KA_boolean), 0, ExtendedKey, 160, 16);//k15k16
            moveLeft(KL_boolean, 17);
            System.arraycopy(booleanArray2ByteArray(KL_boolean), 0, ExtendedKey, 176, 16);//k17k18
            moveLeft(KA_boolean, 17);
            System.arraycopy(booleanArray2ByteArray(KA_boolean), 0, ExtendedKey, 192, 16);//kw()
        } else {
            ExtendedKey = new byte[274];
            for (int i = 0; i < 16; i++)
                KA_byte[i] = (byte) (KL_byte[i] ^ KR_byte[i]);
            roundsWithF(KA_byte, C, 0, 2);
            for (int i = 0; i < 16; i++)
                KA_byte[i] = (byte) (KL_byte[i] ^ KA_byte[i]);
            roundsWithF(KA_byte, C, 16, 2);
            System.arraycopy(KA_byte, 0, KB_byte, 0, 16);
            for (int i = 0; i < 16; i++)
                KB_byte[i] = (byte) (KB_byte[i] ^ KR_byte[i]);
            roundsWithF(KB_byte, C, 32, 2);
            System.arraycopy(KL_byte, 0, ExtendedKey, 0, 16);//kwi
            System.arraycopy(KB_byte, 0, ExtendedKey, 16, 16);//k1k2
            boolean[] KR_boolean = byteArray2BooleanArray(KR_byte);
            moveLeft(KR_boolean, 15);
            System.arraycopy(booleanArray2ByteArray(KR_boolean), 0, ExtendedKey, 32, 16);//k3k4
            boolean[] KA_boolean = byteArray2BooleanArray(KA_byte);
            moveLeft(KA_boolean, 15);
            System.arraycopy(booleanArray2ByteArray(KA_boolean), 0, ExtendedKey, 48, 16);//k5k6
            moveLeft(KR_boolean, 15);
            System.arraycopy(booleanArray2ByteArray(KR_boolean), 0, ExtendedKey, 64, 16);//k1xk2x
            boolean[] KB_boolean = byteArray2BooleanArray(KB_byte);
            moveLeft(KB_boolean, 30);
            System.arraycopy(booleanArray2ByteArray(KB_boolean), 0, ExtendedKey, 80, 16);//k7k8
            boolean[] KL_boolean = byteArray2BooleanArray(KL_byte);
            moveLeft(KL_boolean, 45);
            System.arraycopy(booleanArray2ByteArray(KL_boolean), 0, ExtendedKey, 96, 16);//k9k10
            moveLeft(KA_boolean, 30);
            System.arraycopy(booleanArray2ByteArray(KA_boolean), 0, ExtendedKey, 112, 16);//k11k12
            moveLeft(KL_boolean, 15);
            System.arraycopy(booleanArray2ByteArray(KL_boolean), 0, ExtendedKey, 128, 16);//k3xk4x
            moveLeft(KR_boolean, 30);
            System.arraycopy(booleanArray2ByteArray(KR_boolean), 0, ExtendedKey, 144, 16);//k13k14
            moveLeft(KB_boolean, 30);
            System.arraycopy(booleanArray2ByteArray(KB_boolean),  0, ExtendedKey, 160, 16);//k15k16
            moveLeft(KL_boolean, 17);
            System.arraycopy(booleanArray2ByteArray(KL_boolean), 0, ExtendedKey, 176, 16);//k17k18
            moveLeft(KA_boolean, 32);
            System.arraycopy(booleanArray2ByteArray(KA_boolean), 0, ExtendedKey, 192, 16);//k5xk6x
            moveLeft(KR_boolean, 34);
            System.arraycopy(booleanArray2ByteArray(KA_boolean), 0, ExtendedKey, 208, 16);//k19k20
            moveLeft(KA_boolean, 17);
            System.arraycopy(booleanArray2ByteArray(KA_boolean), 0, ExtendedKey, 224, 16);//k21k22
            moveLeft(KL_boolean, 34);
            System.arraycopy(booleanArray2ByteArray(KL_boolean), 0, ExtendedKey, 240, 16);//k23k24
            moveLeft(KB_boolean, 51);
            System.arraycopy(booleanArray2ByteArray(KA_boolean), 0, ExtendedKey, 256, 16);//kw()
        }
    }

    private static String createPath (String FileName, boolean forEncryption) {
        int i = FileName.length() - 1;
        while (FileName.charAt(i) != '.')
            i--;
        return (forEncryption) ? FileName.substring(0, i) + "_encrypted" + FileName.substring(i) :
                FileName.substring(0, i) + "_decrypted" + FileName.substring(i);
    }

    private static void eK (byte[] block) {
        for (int i = 0; i < 16; i++)
            block[i] = (byte) (block[i] ^ ExtendedKey[i]);
        roundsWithF(block, ExtendedKey, 16, 6);
        byte[] left =  new byte[8], right = new byte[8];
        System.arraycopy(block, 0, left, 0, 8);
        System.arraycopy(block, 8, right, 0, 8);
        FL(left, ExtendedKey, 64);
        FLI(right, ExtendedKey, 72);
        System.arraycopy(left, 0, block, 0, 8);
        System.arraycopy(right, 0, block, 8, 8);
        roundsWithF(block, ExtendedKey, 80, 6);
        System.arraycopy(block, 0, left, 0, 8);
        System.arraycopy(block, 8, right, 0, 8);
        FL(left, ExtendedKey, 128);
        FLI(right, ExtendedKey, 136);
        System.arraycopy(left, 0, block, 0, 8);
        System.arraycopy(right, 0, block, 8, 8);
        roundsWithF(block, ExtendedKey, 144, 6);
        if (!(keyIs128)) {
            System.arraycopy(block, 0, left, 0, 8);
            System.arraycopy(block, 8, right, 0, 8);
            FL(left, ExtendedKey, 192);
            FLI(right, ExtendedKey, 200);
            System.arraycopy(left, 0, block, 0, 8);
            System.arraycopy(right, 0, block, 8, 8);
            roundsWithF(block, ExtendedKey, 208, 6);
        }
        for (int i = 0; i < 8; i++) {
            byte t = block[i];
            block[i] = block[i + 8];
            block[i + 8] = t;
        }
        if (keyIs128)
            for (int i = 0; i < 16; i++)
                block[i] = (byte) (block[i] ^ ExtendedKey[192 + i]);
        else
            for (int i = 0; i < 16; i++)
                block[i] = (byte) (block[i] ^ ExtendedKey[256 + i]);
    }

    private static void add1 (byte[] Add1) {
        for (int i = 15; i >= 0; i--) {
            if (Add1[i] != -1) {
                Add1[i] += 1;
                break;
            }
            else Add1[i] = 0;
        }
    }

    private static void roundsWithF (byte[] block16, byte[] keys, int start, int rounds) {
        byte[] left = new byte[8], right = new byte[8], t = new byte[8];
        System.arraycopy(block16, 0, left, 0, 8);
        System.arraycopy(block16, 8, right, 0, 8);
        for (int i = 0; i < rounds; i++) {
            System.arraycopy(left, 0, t, 0, 8);
            for (int j = 0; j < 8; j++)
                left[j] = (byte) (left[j] ^ keys[start + j + 8 * i]);
            int x1 = S1[Byte2Int(left[0])];
            int x2 = S4[Byte2Int(left[1])];
            int x3 = S3[Byte2Int(left[2])];
            int x4 = S2[Byte2Int(left[3])];
            int x5 = S4[Byte2Int(left[4])];
            int x6 = S3[Byte2Int(left[5])];
            int x7 = S2[Byte2Int(left[6])];
            int x8 = S1[Byte2Int(left[7])];
            left[4] = (byte)(x2 ^ x3 ^ x4 ^ x5 ^ x6 ^ x7);
            left[5] = (byte)(x1 ^ x3 ^ x4 ^ x6 ^ x7 ^ x8);
            left[6] = (byte)(x1 ^ x2 ^ x4 ^ x5 ^ x7 ^ x8);
            left[7] = (byte)(x1 ^ x2 ^ x3 ^ x5 ^ x6 ^ x8);
            left[0] = (byte)(x2 ^ x3 ^ x4 ^ x5 ^ x8);
            left[1] = (byte)(x1 ^ x3 ^ x4 ^ x5 ^ x6);
            left[2] = (byte)(x1 ^ x2 ^ x4 ^ x6 ^ x7);
            left[3] = (byte)(x1 ^ x2 ^ x3 ^ x7 ^ x8);
            for (int j = 0; j < 8; j++)
                left[j] = (byte) (left[j] ^ right[j]);
            System.arraycopy(t, 0, right, 0, 8);
        }
        System.arraycopy(left, 0, block16, 0, 8);
        System.arraycopy(right, 0, block16, 8, 8);
    }

    private static boolean[] byteArray2BooleanArray (byte[] toBoolean) {
        boolean[] small = new boolean[8], big = new boolean[8*toBoolean.length];
        for (int i = 0; i < toBoolean.length; i++) {
            if (toBoolean[i] < 0) {
                small[0] = true;
                toBoolean[i] = (byte)(toBoolean[i]^0x80);
            }
            for (int j = 6; j >= 0; toBoolean[i]/=2, j--)
                small[j + 1] = (toBoolean[i] % 2 == 1);
            System.arraycopy(small, 0, big, 8*i, 8);
            for (int j = 0; j < 8; j++)
                small[j] = false;
        }
        return big;
    }

    private static void moveLeft(boolean[] move, int positions) {
        boolean[] reserve = new boolean[positions];
        System.arraycopy(move, 0, reserve, 0, positions);
        System.arraycopy(move, positions, move, 0, move.length - positions);
        System.arraycopy(reserve, 0, move, move.length - positions, positions);
    }

    private static byte[] booleanArray2ByteArray (boolean[] toByte) {
        int len = toByte.length/8;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++)
            for (int j = 8*i; j < 8*(i + 1); j++)
                if (toByte[j])
                    result[i] += (byte) Math.pow(2, 7 - j % 8);
        return result;
    }

    private static void FL (byte[] block8, byte[] keys, int start) {
        byte[] left = new byte[4], right = new byte[4], t = new byte[4];
        System.arraycopy(block8, 0, left, 0, 4);
        System.arraycopy(block8, 4, right, 0, 4);
        for (int i = 0; i < 4; i++)
            t[i] = (byte) (left[i] & keys[start + i]);
        boolean[] t_boolean = byteArray2BooleanArray(t);
        moveLeft(t_boolean, 1);
        t = booleanArray2ByteArray(t_boolean);
        for (int i = 0; i < 4; i++)
            right[i] = (byte) (t[i] ^ right[i]);
        System.arraycopy(right, 0, block8, 4, 4);
        for (int i = 0; i < 4; i++) {
            right[i] = (byte) (right[i] | keys[start + 4 + i]);
            left[i] = (byte) (left[i] ^ right[i]);
        }
        System.arraycopy(left, 0, block8, 0, 4);
    }

    private static void FLI (byte[] block8, byte[] keys, int start) {
        byte[] left = new byte[4], right = new byte[4], t = new byte[4];
        System.arraycopy(block8, 0, left, 0, 4);
        System.arraycopy(block8, 4, right, 0, 4);
        System.arraycopy(right, 0, t, 0, 4);
        for (int i = 0; i < 4; i++) {
            t[i] = (byte)(t[i] | keys[start + 4 + i]);
            left[i] = (byte)(t[i] ^ left[i]);
        }
        System.arraycopy(left, 0, block8, 0, 4);
        for (int i = 0; i < 4; i ++)
            left[i] = (byte) (left[i] ^ keys[start + i]);
        boolean[] left_boolean = byteArray2BooleanArray(left);
        moveLeft(left_boolean, 1);
        left = booleanArray2ByteArray(left_boolean);
        for (int i = 0; i < 4; i++)
            right[i] = (byte) (right[i] ^ left[i]);
        System.arraycopy(right, 0, block8, 4, 4);
    }

    private static int Byte2Int (byte toInt) {
        return (toInt >= 0) ? toInt : toInt + 256;
    }
}