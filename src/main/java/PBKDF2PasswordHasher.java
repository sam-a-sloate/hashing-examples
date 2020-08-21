import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class PBKDF2PasswordHasher implements PasswordHasher {

	public static final int ITERATION_COUNT = 100000;

	@Override
	public String hash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );
		PBEKeySpec spec = new PBEKeySpec( password.toCharArray(), "abcd".getBytes(StandardCharsets.UTF_8), ITERATION_COUNT, 512 );

		SecretKey key = skf.generateSecret( spec );

		byte[] encoded = key.getEncoded();
		return Base64.getEncoder().encodeToString(encoded);

	}

	@Override
	public boolean verify(String hash, String password)
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		String actualHash = hash(password);
		return hash.equals(actualHash);
	}
}
