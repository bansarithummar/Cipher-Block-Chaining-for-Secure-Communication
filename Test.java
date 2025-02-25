
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Random;
import java.io.*;

public class Test {

	public static void main(String[] args) throws IOException {
		Random rand = new Random();
		int[] key = { 10, 12, 13, 14 }; // instantiating a key
		CBC cbc = new CBC(key); // instantiating a TEA class

		int[] data = new int[2];

		int IV[] = { rand.nextInt(), rand.nextInt() }; // generating a random IV

		FileInputStream fileIN = new FileInputStream("C:\\Users\\path");
		FileOutputStream fileOut = new FileOutputStream("C:\\Users\\path");

		DataInputStream dataIn = new DataInputStream(fileIN);
		DataOutputStream dataOut = new DataOutputStream(fileOut);

		
		boolean firstTime = true; // to know when to apply IV or the previous encrypted block
		int cipher[] = new int[2];
		boolean check = true; // to catch where the reading from the file is stopped
		while (dataIn.available() > 0) {
			try { // readInt is used twice to use 64 bit block
				data[0] = dataIn.readInt();
				data[1] = dataIn.readInt();
				check = true;
				if (firstTime) { // if true, the block is passed with IV to be encrypted by TEA algorithm
					cipher = cbc.encrypt(data, IV);
					firstTime = false; // set firstTime to false sense IV is only encrypted in the first block
				} else
					cipher = cbc.encrypt(data, cipher); // pass the block with the previous encrypted block

				dataOut.writeInt(cipher[0]);
				dataOut.writeInt(cipher[1]);
				check = false;
			} catch (EOFException e) { // excetion is thrown if the file ends and dataIn.readInt() is executed
				if (!check) { // if false, it means last block were not encrypted
					dataOut.writeInt(data[0]);
					dataOut.writeInt(data[1]);
				} else // if true, it means only last half a block is not encrypted
					dataOut.writeInt(data[0]);
			}

		}
		dataIn.close();
		dataOut.close();

		/* ~~~~~~~~~~~~~~~~~~~~~~~Decrypting the Image ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
		DataInputStream dataIn1 = new DataInputStream(new FileInputStream("C:\\Users\\path"));
		DataOutputStream dataOut1 = new DataOutputStream(new FileOutputStream("C:\\Users\\path"));

		int[] copyCipher = new int[2];
		firstTime = true;
		int plain[] = new int[2];
		check = true;

		while (dataIn1.available() > 0) {
			try {
				data[0] = dataIn1.readInt();
				check = true;
				data[1] = dataIn1.readInt();

				if (firstTime) { // if true, the first block is passed with IV to be decrytped
					plain = cbc.decrypt(data, IV);
					firstTime = false; // set first time to false
				} else // if false, the block is passed with the previously encrypted block
					plain = cbc.decrypt(data, copyCipher);

				dataOut1.writeInt(plain[0]);
				dataOut1.writeInt(plain[1]);

				copyCipher[0] = data[0]; // Save the previously encryted block in copyCipher to use it
				copyCipher[1] = data[1];

				check = false;
			} catch (EOFException e) {
				if (!check) {
					dataOut1.writeInt(data[0]);
					dataOut1.writeInt(data[1]);
				} else
					dataOut1.writeInt(data[0]);
				;
			}

		}
		dataIn1.close();
		dataOut1.close();

		fileOut.close();
		fileIN.close();
	}
}
