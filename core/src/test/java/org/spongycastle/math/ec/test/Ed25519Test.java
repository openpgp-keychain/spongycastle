package org.spongycastle.math.ec.test;

import java.math.BigInteger;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.spongycastle.math.ec.custom.djb.Ed25519;
import org.spongycastle.math.ec.custom.djb.Ed25519Point;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECMultiplier;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.ReferenceMultiplier;

public class Ed25519Test extends TestCase
{
    private static final BigInteger q = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819949");
    private static final BigInteger d = new BigInteger("-4513249062541557337682894930092624173785641285191125241628941591882900924598840740");
    private static final BigInteger By = new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960");
    private static final BigInteger Bx = new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202");
    private static final BigInteger[] B = {Bx.mod(q),By.mod(q)};

    public void testOperations()
    {
        ECCurve curve = new Ed25519();
        ECPoint b = curve.createPoint(Bx, By, true);
        ECPoint c = b.twice();
        ECPoint ca = b.add(b);
        ECPoint cc = b.twice();
        ECPoint cca = b.add(b);

        BigInteger[] BB = edwards(B, B);
        assertEquals("x is different", c.getXCoord().toBigInteger(), BB[0]);
        assertEquals("y is different", c.getYCoord().toBigInteger(), BB[1]);

        BigInteger r = BigInteger.valueOf(2);

        ECMultiplier basePointMultiplier = new ReferenceMultiplier();
        ECPoint p = basePointMultiplier.multiply(b, r);

        BigInteger[] Ra = scalarmult(B, r);

        System.out.println("b[x]:" + b.getXCoord().toBigInteger().toString());
        System.out.println("b[y]:" + b.getYCoord().toBigInteger().toString());
        System.out.println("c[x]:" + c.getXCoord().toBigInteger().toString());
        System.out.println("c[y]:" + c.getYCoord().toBigInteger().toString());
        System.out.println("ca[x]:" + ca.getXCoord().toBigInteger().toString());
        System.out.println("ca[y]:" + ca.getYCoord().toBigInteger().toString());
        System.out.println("cc[x]:" + cc.getXCoord().toBigInteger().toString());
        System.out.println("cc[y]:" + cc.getYCoord().toBigInteger().toString());
        System.out.println("cca[x]:" + cca.getXCoord().toBigInteger().toString());
        System.out.println("cca[y]:" + cca.getYCoord().toBigInteger().toString());

        assertEquals("x is different in mult", p.getXCoord().toBigInteger(), Ra[0]);
        assertEquals("y is different in mult", p.getYCoord().toBigInteger(), Ra[1]);
    }

    protected BigInteger[] edwards(BigInteger[] P, BigInteger[] Q) {
        BigInteger x1 = P[0];
        BigInteger y1 = P[1];
        BigInteger x2 = Q[0];
        BigInteger y2 = Q[1];
        BigInteger dtemp = d.multiply(x1).multiply(x2).multiply(y1).multiply(y2);
        dtemp = dtemp.mod(q);
        BigInteger x3 = ((x1.multiply(y2)).add((x2.multiply(y1)))).multiply(BigInteger.ONE.add(dtemp).modInverse(q));
        BigInteger y3 = ((y1.multiply(y2)).add((x1.multiply(x2)))).multiply(BigInteger.ONE.subtract(dtemp).modInverse(q));
        return new BigInteger[]{x3.mod(q), y3.mod(q)};
    }

    public BigInteger[] scalarmult(BigInteger[] P, BigInteger e) {
        if (e.equals(BigInteger.ZERO)) {
            return new BigInteger[]{BigInteger.ZERO, BigInteger.ONE};
        }
        BigInteger[] Q = scalarmult(P, e.divide(BigInteger.valueOf(2)));
        Q = edwards(Q, Q);
        if (e.testBit(0)) Q = edwards(Q, P);
        System.out.println("e:" + e.toString());
        System.out.println("x:" + Q[0].toString());
        System.out.println("y:" + Q[1].toString());
        return Q;
    }

    public static Test suite()
    {
        return new TestSuite(Ed25519Test.class);
    }

}
