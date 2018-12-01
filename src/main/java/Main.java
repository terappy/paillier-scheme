import java.math.BigInteger;
import scheme.Paillier;

public class Main {
    public static void main(String[] args){
        String CHARSET = "UTF-8";
        String planeText = "password";


        try {
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


//            BigInteger m2 = BigInteger.valueOf(20);
//            BigInteger c2 = paillier.encrypt(m2);
//            BigInteger res2 = paillier.decrypt(c2);
//            System.out.println("m2 : "+m2);
//            System.out.println("c2 : "+c2);
//            System.out.println("res2 : "+res2);
//
//            BigInteger c3 = paillier.add(c,c2);
//            BigInteger res3 = paillier.decrypt(c3);
//
//            System.out.println("c3 : "+c3);
//            System.out.println("res3 : "+res3);

            System.out.println("==================");
            paillier.printValues();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
