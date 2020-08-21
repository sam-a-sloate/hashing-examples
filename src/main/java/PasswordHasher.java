import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public interface PasswordHasher {
	String hash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException;
	boolean verify(String hash, String password) throws InvalidKeySpecException, NoSuchAlgorithmException;
}
