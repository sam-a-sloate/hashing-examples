import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class PBKDF2PasswordHasher implements PasswordHasher {

	public static final int ITERATION_COUNT = 100000;
	public static final SecureRandom SECURE_RANDOM = new SecureRandom();
	public static final String SALT_SEPARATOR = "::::::";

	@Override
	public String hash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
		return hash(password, generateNewSalt());
	}

	private String hash(String password, String base64Salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );

		PBEKeySpec spec = new PBEKeySpec( password.toCharArray(), Base64.getDecoder().decode(base64Salt), ITERATION_COUNT, 512);

		SecretKey hash = skf.generateSecret( spec );

		byte[] encodedHash = hash.getEncoded();
		return base64Salt + SALT_SEPARATOR + Base64.getEncoder().encodeToString(encodedHash);
	}

	private String generateNewSalt() {
		byte[] salt = new byte[16];
		SECURE_RANDOM.nextBytes(salt);
		return Base64.getEncoder().encodeToString(salt);
	}

	@Override
	public boolean verify(String hash, String password)
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		String[] saltPlusHash = hash.split(SALT_SEPARATOR);
		String actualHash = hash(password, saltPlusHash[0]);
		return hash.equals(actualHash);
	}
}
