import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class Hashing {

	private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
	public String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = HEX_ARRAY[v >>> 4];
			hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
		}
		return new String(hexChars);
	}

	/**
	 * No Salt is used and the password is hashed using SHA-256
	 *
	 * @param password - text password
	 * @return password hashed with sha-256
	 */
	public String hashSha256NoSalt(String password) throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

		byte[] digest = messageDigest.digest(password.getBytes(StandardCharsets.UTF_8));

		return bytesToHex(digest);
	}

	/**
	 * Repetitive short salt is used. Password+Salt are hashed
	 *
	 * @param password - text password
	 * @return salted password hashed with sha-256
	 */
	public String hashSha256BadSalt(String password) throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

		String passwordWithSalt = "salt" + password; //Same salt is used for every password. Hmmmmmm

		byte[] digest = messageDigest.digest(passwordWithSalt.getBytes(StandardCharsets.UTF_8));

		return bytesToHex(digest);
	}

	/**
	 * Good salt is used. Password + salt are hashed
	 * @param password - text password
	 * @return salted password hashed with sha-256
	 * @throws NoSuchAlgorithmException
	 */
	public String hashSha256GoodSalt(String password) throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

		byte[] salt = generateGoodSalt(); //Notice that a new salt is generated EVERY time

		byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);

		byte[] saltAndPassBytes = new byte[salt.length + passwordBytes.length];

		System.arraycopy(salt, 0, saltAndPassBytes, 0, salt.length);
		System.arraycopy(passwordBytes, 0, saltAndPassBytes, salt.length, passwordBytes.length);
		byte[] digest = messageDigest.digest(saltAndPassBytes);

		return bytesToHex(digest);
	}

	public static byte[] generateGoodSalt() {
		SecureRandom secureRandom = new SecureRandom(); //Notice the use of SecureRandom not Random: https://www.geeksforgeeks.org/random-vs-secure-random-numbers-java/
		byte[] bytes = new byte[16]; //16 byte salt https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#salting
		secureRandom.nextBytes(bytes);
		return bytes;
	}


	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
		Hashing hasher = new Hashing();
		String password = "password";
		String hashedPassword = hasher.hashSha256NoSalt(password);
		System.out.println("Just Hashed Password: " + hashedPassword);

		String hashedWithBadSalt = hasher.hashSha256BadSalt(password);
		System.out.println("Hashed with a bad Salt Password: " + hashedWithBadSalt);


		String hashedWithWellGeneratedSalt = hasher.hashSha256GoodSalt(password);
		System.out.println("Hashed with a good Salt Password: " + hashedWithWellGeneratedSalt);

		PasswordHasher argon2PasswordHasher = new Argon2PasswordHasher();
		String argon2PasswordHash = argon2PasswordHasher.hash(password);
		System.out.println("Argon2 password: " + argon2PasswordHash);
		boolean argon2Verify = argon2PasswordHasher.verify(argon2PasswordHash, password);
		System.out.println("Argon2 verify: " + argon2Verify);


		PasswordHasher bcryptPasswordHasher = new BcryptPasswordHasher();
		String bcryptPasswordHash = bcryptPasswordHasher.hash(password);
		System.out.println("Bcrypt password: " + bcryptPasswordHash);
		boolean bcryptVerify = bcryptPasswordHasher.verify(bcryptPasswordHash, password);
		System.out.println("Bcrypt verify: " + bcryptVerify);

		PasswordHasher pbkdf2PasswordHasher = new PBKDF2PasswordHasher();
		String pbkf2Hash = pbkdf2PasswordHasher.hash(password);
		System.out.println("PBKF2 password: " + pbkf2Hash);
		boolean pbkf2Verify = pbkdf2PasswordHasher.verify(pbkf2Hash, password);
		System.out.println("PBKF2 verify: " + pbkf2Verify);


	}
}
