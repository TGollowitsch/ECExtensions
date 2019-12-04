using System;
using System.Numerics;
using System.Security.Cryptography;

namespace ECExtensions
{
    public class ECFunctions
    {
        public ECCurve Curve { get; private set; }

        private readonly BigInteger a;
        private readonly BigInteger b;
        private readonly BigInteger prime;

        public ECFunctions(ECCurve curve)
        {
            Curve = curve;
            a = new BigInteger(curve.A, true, true);
            b = new BigInteger(curve.B, true, true);
            prime = new BigInteger(curve.Prime, true, true);
        }

        private (BigInteger x, BigInteger y) PointToTuple(ECPoint p) =>
            (new BigInteger(p.X, true, true), new BigInteger(p.Y, true, true));

        private ECPoint TupleToPoint((BigInteger x, BigInteger y) p) =>
            new ECPoint()
            {
                X = p.x.ToByteArray(true, true),
                Y = p.y.ToByteArray(true, true)
            };

        private bool IsOnCurve((BigInteger x, BigInteger y) p) =>
            ((p.y * p.y) - (p.x * p.x * p.x) - (a * p.x) - b).Mod(prime) == 0;

        /// <summary>
        /// Checks whether the point exists on the curve
        /// </summary>
        /// <param name="point">An elliptic curve point</param>
        /// <returns>True if on the curve, otherwise false</returns>
        public bool IsOnCurve(ECPoint point)
        {
            var p = PointToTuple(point);

            return IsOnCurve(p);
        }

        private (BigInteger x, BigInteger y) Negate((BigInteger x, BigInteger y) p)
        {
            p.y = (-p.y).Mod(prime);
            return p;
        }

        /// <summary>
        /// Calculates -P such that P + (-P) = Point at Infinity
        /// </summary>
        /// <param name="point">An elliptic curve point</param>
        /// <returns>The other solution for x on the elliptic curve</returns>
        public ECPoint Negate(ECPoint point)
        {
            if (!IsOnCurve(point))
                throw new Exception();

            var y = new BigInteger(point.Y, true, true);

            return new ECPoint()
            {
                X = point.X,
                Y = (-y).Mod(prime).ToByteArray(true, true)
            };
        }

        private (BigInteger x, BigInteger y) PointAdd((BigInteger x, BigInteger y) p, (BigInteger x, BigInteger y) q) // P + Q = R
        {
            if (!IsOnCurve(p) || !IsOnCurve(p))
                throw new Exception();

            BigInteger m;

            if (p.x == q.x)
            {
                if (p.y != q.y)
                    throw new Exception(); // p + (-p) == 0
                m = (3 * p.x * p.x + a) * (2 * p.y).ModMultInverse(prime);
            }
            else
                m = (p.y - q.y) * (p.x - q.x).ModMultInverse(prime);

            var rX = (m * m - p.x - q.x).Mod(prime);
            var rY = (m * (p.x - rX) - p.y).Mod(prime);
            var r = (rX, rY);

            return IsOnCurve(r) ? r : throw new Exception();
        }

        /// <summary>
        /// Performs a group addition between two elliptic curve points on the same curve
        /// </summary>
        /// <param name="point">Elliptic Curve Point P</param>
        /// <param name="addend">Elliptic Curve Point Q</param>
        /// <returns>Point -R such that P + Q + R = Point at Infinity</returns>
        public ECPoint Add(ECPoint point, ECPoint addend) // P + Q = R
        {
            var p = PointToTuple(point);
            var q = PointToTuple(addend);

            var r = PointAdd(p, q);

            return TupleToPoint(r);
        }

        private (BigInteger x, BigInteger y) ScalarMultiply((BigInteger x, BigInteger y) p, BigInteger n)
        {
            if (!IsOnCurve(p))
                throw new Exception();

            if (n.Mod(prime) == 0)
                throw new Exception();

            (BigInteger x, BigInteger y)? result = new (BigInteger x, BigInteger y)?();
            var addend = p;

            while (n > 0)
            {
                if (!n.IsEven)
                {
                    if (result is null)
                        result = addend;
                    else
                        result = PointAdd(result.Value, addend);
                }
                addend = PointAdd(addend, addend);
                n >>= 1;
            }
            return result.Value;
        }

        /// <summary>
        /// Performs Scalar Multiplication on an Elliptic Curve point using the double-and-add algorithm
        /// </summary>
        /// <param name="point">An elliptic curve point</param>
        /// <param name="n">Any positive integer</param>
        /// <returns>Point H where H = nP (P added to itself n times)</returns>
        public ECPoint Multiply(ECPoint point, BigInteger n)
        {
            var p = PointToTuple(point);
            var result = ScalarMultiply(p, n);
            return TupleToPoint(result);
        }

        public byte[] Serialize(ECPoint point, bool compressedForm)
        {
            if (compressedForm)
            {
                var compressedPoint = new byte[33];

                var y = new BigInteger(point.Y, true, true);

                byte prefix;
                if (y.IsEven)
                    prefix = 0x02; // y is even
                else
                    prefix = 0x03; // y is odd

                compressedPoint[0] = prefix;
                Array.Copy(point.X, 0, compressedPoint, 1, 32);

                return compressedPoint;
            }
            else
            {
                var expandedPoint = new byte[65];

                expandedPoint[0] = 0x04;
                Array.Copy(point.X, 0, expandedPoint, 1, 32);
                Array.Copy(point.Y, 0, expandedPoint, 33, 32);

                return expandedPoint;
            }
        }

        public ECPoint Parse(byte[] serializedPoint)
        {
            ECPoint point;
            point.X = serializedPoint[1..33];

            var prefixByte = serializedPoint[0];
            if (prefixByte == 0x04)
            {
                point.Y = serializedPoint[33..];
            }
            else // https://stackoverflow.com/questions/43629265/deriving-an-ecdsa-uncompressed-public-key-from-a-compressed-one
            {
                var xBytes = serializedPoint[1..33];
                var x = new BigInteger(xBytes, true, true);

                var ySquared = (BigInteger.ModPow(x, 3, prime) + 7).Mod(prime);
                var y = BigInteger.ModPow(ySquared, (prime + 1) / 4, prime);

                if (((prefixByte == 0x02) && !y.IsEven) || ((prefixByte == 0x03) && y.IsEven))
                    y = (y * -1).Mod(prime);

                point.Y = y.ToByteArray(true, true);
            }
            return point;
        }
    }
}
