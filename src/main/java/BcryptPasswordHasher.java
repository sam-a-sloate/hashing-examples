import org.mindrot.jbcrypt.BCrypt;

public class BcryptPasswordHasher implements PasswordHasher {

	public static final int LOG_ROUNDS = 15; //Goal should be time

	@Override
	public String hash(String password) {
		return BCrypt.hashpw(password, BCrypt.gensalt(LOG_ROUNDS));
	}

	@Override
	public boolean verify(String hash, String password) {
		return BCrypt.checkpw(password, hash);
	}
}
