import java.util.Scanner;

public class Test {
    public static void main(String[] args) {
        Scanner in = new Scanner(System.in);
        System.out.println("Введите пароль: ");
        String password = in.nextLine();
        System.out.println("Выбираем цифру:\n1. Зашифровка;\n2. Расшифровка.");
        int eOrDe = in.nextInt();
        if ((eOrDe != 1) && (eOrDe != 2))
            throw new IllegalArgumentException("Неверная цифра.");
        System.out.println("Выбираем алгоритм (написать цифру):\n1. Camellia-128;\n2. Camellia-192;\n3. Camellia-256.");
        int algo = in.nextInt();
        String rubbish = in.nextLine();
        if (algo < 0 || algo > 3)
            throw new IllegalArgumentException("Неверная цифра.");
        System.out.println("Директорию, пожалуйста:");
        String FileName = in.nextLine();
        Camellia.encryptionOrDecryption(FileName, password, algo, eOrDe == 1);
        System.out.println("Дело сделано." + rubbish);
    }
}