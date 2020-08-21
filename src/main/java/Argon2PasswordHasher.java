import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

import java.nio.charset.StandardCharsets;

public class Argon2PasswordHasher implements PasswordHasher{

	private final Argon2 argon2;
	private final int iterations; //increase the number of iterations until the algorithm exceeds execution time once memory + parrelelism is decided
	private final int memory; // RFC recommends 4 GB for backend authentication and 1 GB for frontend authentication
	private final int parrallelism; //twice as many as the number of cores dedicated to hashing passwords

	public Argon2PasswordHasher() {
		this(5, 1024*1024, 8);
	}

	public Argon2PasswordHasher(int iterations, int memory, int parrallelism) {
		this.argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
		this.iterations = iterations;
		this.parrallelism = parrallelism;
		this.memory = memory;
	}

	@Override
	public String hash(String password) { //Argon2 does the salt for you and returns in with the password. No need to manage it!
		return argon2.hash(iterations, memory, parrallelism, password.getBytes(StandardCharsets.UTF_8));
	}

	@Override
	public boolean verify(String password, String hash) {
		return argon2.verify(hash, password.getBytes(StandardCharsets.UTF_8));
	}
}
