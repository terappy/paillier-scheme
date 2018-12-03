import java.math.BigInteger;
import scheme.Paillier;

public class Main {
    public static void main(String[] args){
        String CHARSET = "UTF-8";
        String planeText = "password";
        BigInteger number = BigInteger.valueOf(13);
        BigInteger k = BigInteger.valueOf(5);


        try {
            // -------------
            // for text
            // -------------
            System.out.println("For text");
            System.out.println("----------------");

            Paillier paillier = new Paillier(500);

            BigInteger m = new BigInteger(planeText.getBytes(CHARSET));
            BigInteger c = paillier.encrypt(m);
            BigInteger res = paillier.decrypt(c);
            String resStr = new String(res.toByteArray(), CHARSET);

            System.out.println("planeText : "+planeText);
            System.out.println("m : "+m);
            System.out.println("c : "+c);
            System.out.println("res : "+res);
            System.out.println("resStr : "+resStr);

            System.out.println("==================");

            System.out.println(paillier);

            System.out.println("==================");

            // -------------
            // for number
            // -------------
            System.out.println("For number");
            System.out.println("----------------");

            Paillier paillier2 = new Paillier(500);

            BigInteger m2 = number;
            BigInteger c2 = paillier2.encrypt(m2);
            BigInteger calc = paillier2.multiplyConst(c2, k);
            BigInteger res2 = paillier2.decrypt(c2);
            BigInteger clacRes = paillier2.decrypt(calc);

            System.out.println("number : "+m2);
            System.out.println("k : "+k);
            System.out.println("c2 : "+c2);
            System.out.println("res2 : "+res2);
            System.out.println("calc : "+calc);
            System.out.println("calcRes : "+clacRes);

            System.out.println("==================");
            System.out.println(paillier2);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
