import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordManager {

    static final Scanner sc = new Scanner(System.in);
    static final String USER_FILE = "master.dat";
    static final String DATA_FILE = "credentials.dat";
    static String currentKey;

    public static void main(String[] args) {
        System.out.println("======================================");
        System.out.println("        SECURE PASSWORD MANAGER");
        System.out.println("======================================");

        while (true) {
            System.out.println();
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Enter choice: ");

            String choice = sc.nextLine();

            try {
                switch (choice) {
                    case "1":
                        register();
                        break;
                    case "2":
                        if (login()) {
                            dashboard();
                        }
                        break;
                    case "3":
                        System.out.println("Application closed.");
                        return;
                    default:
                        System.out.println("Invalid choice.");
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
    }

    static void register() throws Exception {
        if (Files.exists(Paths.get(USER_FILE))) {
            System.out.println();
            System.out.println("A master account already exists.");
            System.out.println("Please use Login.");
            return;
        }

        System.out.println();
        System.out.println("--------- REGISTER ---------");
        System.out.print("Create master password: ");

        String password = sc.nextLine();

        if (password.length() < 6) {
            System.out.println("Password must contain at least 6 characters.");
            return;
        }

        byte[] salt = generateSalt();
        String hash = hashPassword(password, salt);

        try (DataOutputStream out =
                 new DataOutputStream(new FileOutputStream(USER_FILE))) {
            out.writeUTF(Base64.getEncoder().encodeToString(salt));
            out.writeUTF(hash);
        }

        currentKey = hash;
        System.out.println("Registration successful!");
        System.out.println("You can now login.");
    }

    static boolean login() throws Exception {
        if (!Files.exists(Paths.get(USER_FILE))) {
            System.out.println();
            System.out.println("No account found.");
            System.out.println("Please register first.");
            return false;
        }

        System.out.println();
        System.out.println("----------- LOGIN -----------");
        System.out.print("Enter master password: ");

        String password = sc.nextLine();

        String storedSalt;
        String storedHash;

        try (DataInputStream in =
                 new DataInputStream(new FileInputStream(USER_FILE))) {
            storedSalt = in.readUTF();
            storedHash = in.readUTF();
        }

        byte[] salt = Base64.getDecoder().decode(storedSalt);
        String enteredHash = hashPassword(password, salt);

        if (enteredHash.equals(storedHash)) {
            currentKey = storedHash;
            System.out.println();
            System.out.println("Login successful!");
            System.out.println("Access granted.");
            return true;
        } else {
            System.out.println();
            System.out.println("Password does not match.");
            System.out.println("Access denied. Please try again.");
            return false;
        }
    }

    static void dashboard() throws Exception {
        while (true) {
            System.out.println();
            System.out.println("================================");
            System.out.println("           DASHBOARD");
            System.out.println("================================");
            System.out.println("1. Add Credential");
            System.out.println("2. View Credentials");
            System.out.println("3. Edit Credential");
            System.out.println("4. Delete Credential");
            System.out.println("5. Logout");
            System.out.print("Enter choice: ");

            String choice = sc.nextLine();

            switch (choice) {
                case "1":
                    addCredential();
                    break;
                case "2":
                    viewCredentials();
                    break;
                case "3":
                    editCredential();
                    break;
                case "4":
                    deleteCredential();
                    break;
                case "5":
                    currentKey = null;
                    System.out.println();
                    System.out.println("Logged out safely.");
                    return;
                default:
                    System.out.println("Invalid choice.");
            }
        }
    }

    static void addCredential() throws Exception {
        System.out.println();
        System.out.println("--------- ADD CREDENTIAL ---------");

        System.out.print("Website/App: ");
        String website = sc.nextLine();

        System.out.print("Username/Email: ");
        String username = sc.nextLine();

        System.out.print("Password: ");
        String password = sc.nextLine();

        String encryptedPassword = encrypt(password, currentKey);

        try (FileWriter fw = new FileWriter(DATA_FILE, true)) {
            fw.write(website + "|" + username + "|" + encryptedPassword + "\n");
        }

        System.out.println("Credential added successfully.");
    }

    static void viewCredentials() throws Exception {
        System.out.println();
        System.out.println("--------- SAVED CREDENTIALS ---------");

        File file = new File(DATA_FILE);

        if (!file.exists()) {
            System.out.println("No credentials found.");
            return;
        }

        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;
        int count = 1;

        while ((line = br.readLine()) != null) {
            String[] data = line.split("\\|", -1);

            if (data.length == 3) {
                String password = decrypt(data[2], currentKey);

                System.out.println();
                System.out.println("Credential " + count);
                System.out.println("Website : " + data[0]);
                System.out.println("Username: " + data[1]);
                System.out.println("Password: " + password);

                count++;
            }
        }

        br.close();

        if (count == 1) {
            System.out.println("No credentials found.");
        }
    }

    static void editCredential() throws Exception {
        File file = new File(DATA_FILE);

        if (!file.exists()) {
            System.out.println("No credentials found.");
            return;
        }

        List<String> records = new ArrayList<>();
        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;

        while ((line = br.readLine()) != null) {
            records.add(line);
        }
        br.close();

        if (records.isEmpty()) {
            System.out.println("No credentials found.");
            return;
        }

        displayRecords(records);

        System.out.print("Enter credential number to edit: ");
        int number = Integer.parseInt(sc.nextLine());

        if (number < 1 || number > records.size()) {
            System.out.println("Invalid number.");
            return;
        }

        System.out.print("New website/app: ");
        String website = sc.nextLine();

        System.out.print("New username/email: ");
        String username = sc.nextLine();

        System.out.print("New password: ");
        String password = sc.nextLine();

        String encrypted = encrypt(password, currentKey);

        records.set(number - 1,
                website + "|" + username + "|" + encrypted);

        saveRecords(records);
        System.out.println("Credential updated successfully.");
    }

    static void deleteCredential() throws Exception {
        File file = new File(DATA_FILE);

        if (!file.exists()) {
            System.out.println("No credentials found.");
            return;
        }

        List<String> records = new ArrayList<>();
        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;

        while ((line = br.readLine()) != null) {
            records.add(line);
        }
        br.close();

        if (records.isEmpty()) {
            System.out.println("No credentials found.");
            return;
        }

        displayRecords(records);

        System.out.print("Enter credential number to delete: ");
        int number = Integer.parseInt(sc.nextLine());

        if (number < 1 || number > records.size()) {
            System.out.println("Invalid number.");
            return;
        }

        records.remove(number - 1);
        saveRecords(records);

        System.out.println("Credential deleted successfully.");
    }

    static void displayRecords(List<String> records) throws Exception {
        int count = 1;

        for (String record : records) {
            String[] data = record.split("\\|", -1);

            if (data.length == 3) {
                System.out.println(count + ". " + data[0] + " - " + data[1]);
                count++;
            }
        }
    }

    static void saveRecords(List<String> records) throws IOException {
        FileWriter fw = new FileWriter(DATA_FILE);

        for (String record : records) {
            fw.write(record + "\n");
        }

        fw.close();
    }

    static byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    static String hashPassword(String password, byte[] salt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);

        byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));

        StringBuilder sb = new StringBuilder();

        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }

        return sb.toString();
    }

    static String encrypt(String password, String keyString) throws Exception {
        byte[] keyBytes = hexToBytes(keyString);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] encrypted =
                cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(iv)
                + ":"
                + Base64.getEncoder().encodeToString(encrypted);
    }

    static String decrypt(String encryptedData, String keyString) throws Exception {
        String[] parts = encryptedData.split(":");

        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encrypted = Base64.getDecoder().decode(parts[1]);

        byte[] keyBytes = hexToBytes(keyString);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        byte[] decrypted = cipher.doFinal(encrypted);

        return new String(decrypted, StandardCharsets.UTF_8);
    }

    static byte[] hexToBytes(String hex) {
        byte[] result = new byte[hex.length() / 2];

        for (int i = 0; i < hex.length(); i += 2) {
            result[i / 2] = (byte) Integer.parseInt(
                    hex.substring(i, i + 2), 16);
        }

        return result;
    }
}
