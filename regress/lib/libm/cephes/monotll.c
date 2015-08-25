/*	$OpenBSD: monotll.c,v 1.2 2011/07/08 16:49:05 martynas Exp $	*/

/*
 * Copyright (c) 2008 Stephen L. Moshier <steve@moshier.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* monotll.c
   Floating point function test vectors.
   128-bit long double version.

   Arguments and function values are synthesized for NPTS points in
   the vicinity of each given tabulated test point.  The points are
   chosen to be near and on either side of the likely function algorithm
   domain boundaries.  Since the function programs change their methods
   at these points, major coding errors or monotonicity failures might be
   detected.

   August, 1998
   S. L. Moshier  */

#include <float.h>

#if	LDBL_MANT_DIG == 113
/* Unit of error tolerance in test[i].thresh.  */
static long double MACHEPL = 1.9259299443872358530559779425849273185381E-34L;
/* How many times the above error to allow before printing a complaint.
   If TOL < 0, consider absolute error instead of relative error. */
#define TOL 4
/* Number of test points to generate on each side of tabulated point.  */
#define NPTS 100



#include <stdio.h>
#include <string.h>

/* Avoid including math.h.  */
long double frexpl (long double, int *);
long double ldexpl (long double, int);

/* Functions of one variable.  */
long double expl (long double);
long double expm1l (long double);
long double logl (long double);
long double log1pl (long double);
long double sinl (long double);
long double cosl (long double);
long double tanl (long double);
long double atanl (long double);
long double asinl (long double);
long double acosl (long double);
long double sinhl (long double);
long double coshl (long double);
long double tanhl (long double);
long double asinhl (long double);
long double acoshl (long double);
long double atanhl (long double);
long double lgammal (long double);
long double tgammal (long double);
long double fabsl (long double);
long double floorl (long double);
long double j0l (long double);
long double y0l (long double);
long double j1l (long double);
long double y1l (long double);
long double jnl (int, long double);
long double ynl (int, long double);

/* Data structure of the test.  */
struct oneargument
  {
    char *name;			/* Name of the function. */
    long double (*func) (long double); /* Function call.  */
    long double arg1;		/* Function argument, assumed exact.  */
    long double answer1;	/* Exact number, close to function value.  */
    long double answer2;	/* answer1 + answer2 has extended precision. */
    long double derivative;	/* dy/dx evaluated at x = arg1. */
    /* Error report threshold. 2 => 1 ulp approximately
       if thresh < 0 then consider absolute error instead of relative error. */
    int thresh;

  };



static struct oneargument test1[] =
{
  {"exp", expl, 1.0L, 2.7182769775390625L,
   4.85091998273536028747135266249775725E-6L,
   2.71828182845904523536028747135266250E0L, TOL},
  {"exp", expl, -1.0L, 3.678741455078125e-1L,
   5.29566362982159552377016146086744581E-6L,
   3.67879441171442321595523770161460867E-1L, TOL},  
  {"exp", expl, 0.5L, 1.648712158203125L,
   9.11249700314684865078781416357165378E-6L,
   1.64872127070012814684865078781416357L, TOL},
  {"exp", expl, -0.5L, 6.065216064453125e-1L,
   9.05326732092360379953499118045344192E-6L,
   6.06530659712633423603799534991180453E-1L, TOL},
  {"exp", expl, 2.0L, 7.3890533447265625L,
   2.75420408772723042746057500781318032E-6L,
   7.38905609893065022723042746057500781E0L, TOL},
  {"exp", expl, -2.0L, 1.353302001953125e-1L,
   5.08304130019189399949497248440340763E-6L,
   1.35335283236612691893999494972484403E-1L, TOL},
  {"expm1", expm1l, 1.0L, 1.7182769775390625L,
   4.85091998273536028747135266249775725E-6L,
   2.71828182845904523536028747135266250E0L, TOL},
  {"expm1", expm1l, 0.5L, 0.648712158203125L,
   9.11249700314684865078781416357165378E-6L,
   1.64872127070012814684865078781416357L, TOL},
  {"expm1", expm1l, 2.0L, 6.3890533447265625L,
   2.75420408772723042746057500781318032E-6L,
   7.38905609893065022723042746057500781E0L, TOL},
  {"log", logl, 1.41421356237309504880168872420969798L,
   3.465728759765625E-1L,
   7.14303410154708616060729088217412434E-7L,
   7.07106781186547524400844362104849086E-1L, TOL},
  {"log", logl, 7.07106781186547524400844362104848992E-1L,
   -3.46588134765625E-1L,
   1.45444856523452913839392709116493369E-5L,
   1.41421356237309504880168872420969817E0L, TOL},
  {"log1p", log1pl, 0.41421356237309504880168872420969798L,
   3.465728759765625E-1L,
   7.14303410154708616060729088217412434E-7L,
   7.07106781186547524400844362104849086E-1L, TOL},
  {"sin", sinl, 7.85398163397448309615660845819875699E-1L,
   7.0709228515625E-1L,
   1.44960302975244008443621048490239551E-5L,
   7.07106781186547524400844362104849055E-1, TOL},
  {"sin", sinl, -7.85398163397448309615660845819875699E-1L,
   -7.071075439453125E-1L,
   7.62758764975599155637895150976044903E-7L,
   7.07106781186547524400844362104849055E-1L, TOL},
  {"sin", sinl, 1.57079632679489661923132169163975140E0L,
   9.999847412109375E-1L,
   1.52587890625E-5L,
   0.0L, TOL},
  {"sin", sinl, -1.57079632679489661923132169163975140E0L,
   -1.0L,
   0.0L,
   0.0L, TOL},
  {"sin", sinl, 4.71238898038468985769396507491925433E0L,
   -1.0L,
   0.0L,
   0.0L, TOL},
  {"sin", sinl, -4.71238898038468985769396507491925420E0L,
   1.0L,
   0.0L,
   0.0L, TOL},
  {"cos", cosl, 3.92699081698724154807830422909937850E-1L,
   9.238739013671875E-1L,
   5.63114409925612818318939678829097061E-6L,
   -3.82683432365089771728459984030398857E-1L, TOL},
  {"cos", cosl, 7.85398163397448309615660845819875699E-1L,
   7.0709228515625E-1L,
   1.44960302975244008443621048490546146E-5L,
   -7.07106781186547524400844362104849024E-1L, TOL},
  {"cos", cosl, 1.17809724509617246442349126872981355E0L,
   3.826751708984375E-1L,
   8.26146665227172845998403039889680525E-6L,
   -9.23879532511286756128183189396788274E-1L, TOL},
  {"cos", cosl, 1.96349540849362077403915211454968925E0L,
   -3.826904296875E-1L,
   6.99732241022827154001596960118331183E-6L,
   -9.23879532511286756128183189396788308E-1L, TOL},
  {"cos", cosl, 2.35619449019234492884698253745962710E0L,
   -7.071075439453125E-1L,
   7.62758764975599155637895151006704382E-7L,
   -7.07106781186547524400844362104849085E-1L, TOL},
  {"cos", cosl, 2.74889357189106908365481296036956495E0L,
   -9.2388916015625E-1L,
   9.62764496324387181681060321174221497E-6L,
   -3.82683432365089771728459984030398937E-1L, TOL},
  {"cos", cosl, 3.14159265358979323846264338327950280E0L,
   -1.0L,
   0.0L,
   0.0L, TOL},
  {"tan", tanl, 7.8539816339744830961566084581987569936977E-1L,
   9.999847412109375E-1L,
   1.5258789062499999999999999999956640949349E-5L,
   2.0L, TOL},
  {"tan", tanl, 1.1780972450961724644234912687298135490547E0L,
   2.4141998291015625L,
   1.3733271532548801688724209697856514083701E-5L,
   6.8284271247461900976033774484193950849601E0L, TOL},
  {"tan", tanl, 1.96349540849362077403915211454968925E0L,
   -2.414215087890625L,
   1.52551752995119831127579030155133768E-6L,
   6.82842712474619009760337744841939794E0L, TOL},
  {"tan", tanl, 2.35619449019234492884698253745962710E0L,
   -1.0000152587890625L,
   1.52587890624999999999999999998699228E-5L,
   2.0L, TOL},
  {"tan", tanl, 2.74889357189106908365481296036956495E0L,
   -4.14215087890625E-1L,
   1.52551752995119831127579030183253332E-6L,
   1.17157287525380990239662255158060392E0L, TOL},
  {"atan", atanl, 4.14213562373095048801688724209698081E-1L,
   3.926849365234375E-1L,
   1.41451752866548078304229099378622950E-5L,
   8.53553390593273762200422181052424518E-1L, TOL},
  {"atan", atanl, 1.0L,
   7.853851318359375E-1L,
   1.30315615108096156608458198757210493E-5L,
   0.5L, TOL},
  {"atan", atanl, 2.41421356237309504880168872420969818E0L,
   1.1780853271484375L,
   1.19179477349644234912687298135959800E-5L,
   1.46446609406726237799577818947575470E-1L, TOL},
  {"atan", atanl, -2.41421356237309504880168872420969818E0L,
   -1.1781005859375L,
   3.34084132753557650873127018640402003E-6L,
   1.46446609406726237799577818947575470E-1L, TOL},
  {"atan", atanl, -1.0L,
   -7.85400390625E-1L,
   2.22722755169038433915418012427895071E-6L,
   0.5L, TOL},
  {"atan", atanl, -4.14213562373095048801688724209698081E-1L,
   -3.927001953125E-1L,
   1.11361377584519216957709006213770502E-6L,
   8.53553390593273762200422181052424518E-1L, TOL},
  {"asin", asinl, 3.82683432365089771728459984030398880E-1L,
   3.926849365234375E-1L,
   1.41451752866548078304229099378750938E-5L,
   1.08239220029239396879944641073277885E0L, TOL},
  {"asin", asinl, 0.5L,
   5.23590087890625E-1L,
   8.68770767387307710723054658381403286E-6L,
   1.15470053837925152901829756100391491E0L, TOL},
  {"asin", asinl, 7.07106781186547524400844362104848992E-1L,
   7.853851318359375E-1L,
   1.30315615108096156608458198756544240E-5L,
   1.41421356237309504880168872420969798E0L, TOL},
  {"asin", asinl, 9.23879532511286756128183189396788310E-1L,
   1.1780853271484375L,
   1.19179477349644234912687298136415266E-5L,
   2.61312592975275305571328634685437469E0L, TOL},
  {"asin", asinl, -0.5L,
   -5.236053466796875E-1L,
   6.57108138862692289276945341618596714E-6L,
   1.15470053837925152901829756100391491E0L, TOL},
  {"asin", asinl, 1.16415321826934814453125E-10L,
   1.16415321826934814453125E-10L,
   2.62953635073670601805513180586984061E-31L,
   1.00000000000000000000677626357803440E0L, TOL},
  {"asin", asinl, 0.625L,
   6.751251220703125E-1L,
   6.41086671914720905626529438801420419E-6L,
   1.28102523044069706786602935814149630E0L, TOL},
  {"asin", asinl, 9.74999999999999999999999999999999981E-1L,
   1.346710205078125L,
   1.08364149523595315129076204973231659E-5L,
   4.50035160370409562029946413944745541E0L, TOL},
  {"acos", acosl, 1.95090322016128267848284868477022248E-1L,
   1.3744354248046875L,
   1.13611408470418274064801847825042255E-5L,
   -1.01959115820831833788387960797568783E0L, TOL},
  {"acos", acosl, 3.82683432365089771728459984030398880E-1L,
   1.1780853271484375L,
   1.19179477349644234912687298135670048E-5L,
   -1.08239220029239396879944641073277885E0L, TOL},
  {"acos", acosl, 0.5L,
   1.0471954345703125L,
   2.11662628524615421446109316762806572E-6L,
   -1.15470053837925152901829756100391491E0L, TOL},
  {"acos", acosl, 7.07106781186547524400844362104848992E-1L,
   7.853851318359375E-1L,
   1.30315615108096156608458198757876746E-5L,
   -1.41421356237309504880168872420969798E0L, TOL},
  {"acos", acosl, 9.23879532511286756128183189396788310E-1L,
   3.926849365234375E-1L,
   1.41451752866548078304229099378005720E-5L,
   -2.61312592975275305571328634685437469E0L, TOL},
  {"acos", acosl, 9.80785280403230449126182236134239047E-1L,
   1.963348388671875E-1L,
   1.47019821745774039152114549688769794E-5L,
   -5.12583089548301235759217259235540119E0L, TOL},
  {"acos", acosl, -0.5L,
   2.094390869140625L,
   4.23325257049230842892218633525613145E-6L,
   -1.15470053837925152901829756100391491E0L, TOL},
  {"sinh", sinhl, 1.0L,
   1.1751861572265625L,
   1.50364172389568823818505956008151557E-5L,
   1.54308063481524377847790562075706168E0L, TOL},
  {"sinh", sinhl, 11355.5L,
   2.13776152623792146713900550884909252E4931L,
   9.07106102767577900425552629248457689E4896L,
   2.13776152623792146713900550884909261E4931L, TOL},
  {"sinh", sinhl, 2.22044604925031308084726333618164062E-16L,
   2.22044604925031308084726333618164062E-16L,
   1.82460737542293889443193956157541613E-48L,
   1.00000000000000000000000000000002465E0L, TOL},
  {"sinh", sinhl, 40.0L,
   1.17692633418509992E17L, 7.039499553745174001302586809814832360E-1L,
   1.176926334185099927039499553745174044E17L, TOL},
  {"sinh", sinhl, 6.938893903907228377647697925567626953E-18L, /* 2^-57 */
   6.938893903907228377647697925567626953E-18L,
   5.568259812692074262792784306565587261E-53L, 1.0L, TOL},
  {"sinh", sinhl, 11356.375L,
   5.1282233096855457613267954696602303826729E4931L,
   6.8582733554584347269625352341976754246942E4896L,
   5.1282233096855457613267954696602304512556E4931L, TOL},
  {"cosh", coshl, 40.0L,
   1.176926334185099927039499553745174054E17L,
   -1.036733679609227143506056540471143597E-18L,
   1.176926334185099927039499553745174001E17L, TOL},
  {"cosh", coshl, 6.938893903907228377647697925567626953E-18L,
   1.0L, 2.407412430484044816319972428231159158E-35L,
   6.938893903907228377647697925567627009E-18L, TOL},
  {"cosh", coshl, 11356.375L,
    5.128223309685545761326795469660230383E4931L,
    6.858273355458434726962535234197675425E4896L,
    5.128223309685545761326795469660230451E4931L, TOL},
  {"cosh", coshl, 11355.5L,
   2.13776152623792146713900550884909252E4931L,
   9.07106102767577900425552629248457689E4896L,
   2.13776152623792146713900550884909261E4931L, TOL},
  {"cosh", coshl, 1.0L,
   1.5430755615234375L,
   5.07329180627847790562075706168260153E-6L,
   1.17520119364380145688238185059560082E0L, TOL},
  {"cosh", coshl, 0.5L,
   1.12762451171875L,
   1.45348763078522622516140267201254785E-6L,
   5.21095305493747361622425626411491559E-1L, TOL},
  {"tanh", tanhl, 0.5L,
   4.621124267578125E-1L,
   4.73050219725850231848364367254873029E-6L,
   7.86447732965927410149698934343636102E-1L, TOL},
  {"tanh", tanhl, 5.49306144334054845697622618461262805E-1L,
   4.999847412109375E-1L,
   1.52587890624999999999999999999648170E-5L,
   7.50000000000000000000000000000000035E-1L, TOL},
  {"tanh", tanhl, 0.625L,
   5.54595947265625E-1L,
   3.77508375729399903909532308359605810E-6L,
   6.92419147969988069630753311573341685E-1L, TOL},
  {"tanh", tanhl, 40.0L,
   1.0L,
   -3.609702775690830344624256714700054777E-35L,
   7.219405551381660689248513429400109424E-35L, TOL},
  {"tanh", tanhl, 6.9388939039072283776476979255676269531250E-18L, /* 2^-57 */
   6.9388939039072283776476979255676269531250E-18L,
   -1.1136519625384148525585568613131174280582E-52L,
   9.9999999999999999999999999999999995185175E-1L, TOL},
  {"tanh", tanhl, 2.775557561562891351059079170227050781E-17L, /* 2^-55 */
   2.775557561562891351059079170227050781E-17L,
   -7.127372560245855056374763912403949481E-51L,
   9.999999999999999999999999999999992296E-1L, TOL},
  {"tanh", tanhl, 1.0L,
   7.615814208984375e-1L,
   1.273505732738811945828260479359041277E-5L,
   4.199743416140260693944967390417014449E-1L, TOL},
  {"asinh", asinhl, 0.5L,
   4.81201171875E-1L,
   1.06531846034474977589134243684231352E-5L,
   8.94427190999915878563669467492510494E-1L, TOL},
  {"asinh", asinhl, 1.0L,
   8.813629150390625E-1L,
   1.06719804805252326093249797923090282E-5L,
   7.07106781186547524400844362104849039E-1L, TOL},
  {"asinh", asinhl, 2.0L,
   1.443634033203125L,
   1.44197568534249327674027310526940555E-6L,
   4.47213595499957939281834733746255247E-1L, TOL},
  {"asinh", asinhl, 1.3877787807814456755295395851135253906250E-17L, /*2^-56*/
   1.3877787807814456755295395851135253906250E-17L,
   -4.4546078501536594102342274452524694119585E-52L,
   9.9999999999999999999999999999999990370350E-1L, TOL},
  {"asinh", asinhl, 1.8014398509481984E16L,
   38.1230926513671875L,
   2.2794298045179477666801997120145244851447E-6L,
   5.5511151231257827021181583404540930096529E-17L, TOL},
  {"acosh", acoshl, 2.0L,
   1.31695556640625L,
   2.33051856670862504634730796844402698E-6L,
   5.77350269189625764509148780501957456E-1L, TOL},
  {"acosh", acoshl, 1.5L,
   9.624176025390625E-1L,
   6.04758014439499551782684873684627037E-6L,
   8.94427190999915878563669467492510494E-1L, TOL},
  {"acosh", acoshl, 1.03125L,
   2.493438720703125E-1L,
   9.62177257298785143907541001884302707E-6L,
   3.96911150685467059808817882107262579E0L, TOL},
  {"acosh", acoshl, 2.68435456e8L,  /* 2 ^ 28 */
   20.10125732421875L,
   1.091201966396963028457033350626731006E-5L,
   3.725290298461914088349394142282115109E-9L, TOL},
  {"acosh", acoshl, 1.8014398509481984e16L, /* 2 ^ 54 */
   38.1230926513671875L,
   2.279429804517947766680199710473780530E-6L,
   5.551115123125782702118158340454110115E-17L, TOL},
  {"acosh", acoshl, 1.073741824e9L, /* 2^30 */
   21.487548828125L,
   1.376923330459171735533070637272346848E-5L,
   9.313225746154785160288967834731580446E-10L, TOL},
  {"atanh", atanhl, 0.5L,
   5.493011474609375E-1L,
   4.99687311734569762261846126285232375E-6L,
   1.33333333333333333333333333333333333E0L, TOL},
  {"atanh", atanhl, 6.938893903907228377647697925567626953125E-18,
   6.938893903907228377647697925567626953125E-18, /* 2^-57 */
   1.1136519625384148525585568613131174816786E-52, 1.0, TOL},
#if 0
  {"j0", j0l, 16.0L, -1.749114990234375e-1L,
    1.24250398083151715974822741805925455E-5L,
   -9.03971756613041862386833024580760244E-2L, -2},
  {"j0", j0l, 8.0L, 1.716461181640625E-1L,
    4.68897349140609086940785197200106842E-6L,
   -2.34636346853914624381276651590454612E-1L, -2},
  {"j0", j0l, 5.33333333333333333333333333333333333E0L,
   -6.427001953125e-2L,
   2.71515994768793872858212682917411767E-6L,
   3.46125605116223455248039758589625114E-1L, -2},
  {"j0", j0l, 4.0L, -3.9715576171875e-1L,
   5.95185490262771340923154830195802438E-6L,
   6.60433280235491361431854208032750287E-2L, -2},
  {"j0", j0l, 3.2L, -3.201904296875e-1L,
   2.26003037709271056745460231434000663E-6L,
   -2.61343248780504837362986742359905319E-1L, -2},
  {"j0", j0l, 2.66666666666666666666666666666666667E0L,
   -1.275634765625e-1L,
   2.48895584953746034929481550434723427E-6L,
   -4.51651148392987785778929732830311060E-1L, -2},
  {"j0", j0l, 2.28571428571428571428571428571428571E0L,
   6.3262939453125e-2L,
   7.41898014310740285267270594759284975E-6L,
   -5.42395540605083481518545728422177515E-1L, -2},
  {"j0", j0l, 2.0L,
   2.23876953125e-1L,
   1.38260162356680518274546499486258252E-5L,
   -5.76724807756873387202448242269137087E-1L, -2},
  {"y0", y0l, 16.0L,
   9.58099365234375e-2L,
   1.06055727490314207096590322941832776E-6L,
   -1.77975168939416859630601904359871915E-1L, -2},
  {"y0", y0l, 8.0L,
   2.235107421875e-1L,
   1.07472000662205273234004986203592748E-5L,
   1.58060461731247494255555266187483550E-1L, -2},
  {"y0", y0l, 5.33333333333333333333333333333333333E0L,
   -3.387451171875e-1L,
   1.48763307492243286439161163883136261E-5L,
   -3.30338692743198039852173817311267913E-2L, -2},
  {"y0", y0l, 4.0L,
   -1.69525146484375E-2L,
    1.17753233725080963648655528467817595E-5L,
   -3.97925710557100005253979972450791852E-1L, -2},
  {"y0", y0l, 3.2L,
    3.070526123046875E-1L,
    6.37827715583546999256417236405953385E-7L,
   -3.70711338441274693924314235987044508E-1L, -2},
  {"y0", y0l, 2.66666666666666666666666666666666667E0L,
   4.67864990234375E-1L,
   1.52461165366402773840048623192120982E-5L,
   -2.14907152209457967672108494960545800E-1L, -2},
  {"y0", y0l, 2.28571428571428571428571428571428571E0L,
   5.18768310546875E-1L,
   3.23404086137065314580351322765266943E-6L,
   -4.51747395962233519705260050662299281E-2L, -2},
  {"y0", y0l, 2.0L,
   5.103607177734375E-1L,
   1.49548763076195966065927271578732681E-5L,
   1.07032431540937546888370772277476637E-1L, -2},
  {"j1", j1l, 16.0L, 
   9.039306640625e-2L,
   4.1092550541862386833024580760244495945291E-6L,
   -1.8054889746246069646832022412944915898260E-1L, -2},
  {"j1", j1l, 8.0L,
    2.346343994140625e-1L,
    1.9474398521243812766515904546115487521615E-6L,
   1.4232126378081457804320982640316517462483E-1L, -2},
  {"j1", j1l, 5.3333333333333333333333333333333330765427E0L,
   -3.4613037109375e-1L,
   4.7659775265447519602414103748858036315250E-6L,
   6.3124658798958579773603686238379727242328E-4L, -2},
  {"j1", j1l, 4.0L,
   -6.60552978515625e-2L,
   1.1969828013363856814579196724971272576580E-5L,
   -3.8063897785796008825079441325087928479376E-1L, -2},
  {"j1", j1l, 3.2000000000000000000000000000000001540744E0L,
   2.613372802734375e-1L,
   5.9685070673373629867423599052573498655055E-6L,
   -4.0185793490103066896536590238515608924925E-1L, -2},
  {"j1", j1l, 2.6666666666666666666666666666666665382713E0L,
   4.516448974609375e-1L,
   6.2509320502857789297328303110978154167062E-6L,
   -2.9693016825402088220674935499586226461144E-1L, -2},
  {"j1", j1l, 2.2857142857142857142857142857142856042326E0L,
   5.42388916015625e-1L,
   6.6245894584815185457284221775341820978577E-6L,
   -1.7402769058145591576151108347875503008807E-1L, -2},
  {"j1", j1l, 2.0L,
   5.7672119140625e-1L,
   3.6163506233872024482422691370869203026897E-6L,
   -6.4471624737201025549396666484619917634997E-2L, -2},
  {"y1", y1l, 16.0L, 
   1.779632568359375e-1L,
   1.1912103479359630601904359871915459722520E-5L,
   8.4687549021998849415158346880737423611524E-2L, -2},
  {"y1", y1l, 8.0L,
   -1.580657958984375e-1L,
    5.3341671900057444447338125164496726559505E-6L,
    2.4327904710397215730926780877205580306573E-1L, -2},
  {"y1", y1l, 5.3333333333333333333333333333333330765427E0L,
   3.302001953125e-2L,
   1.3849743069803985217381731126879849266308E-5L,
   -3.4492409134568573891858434295819796816112E-1L, -2},
  {"y1", y1l, 4.0L,
   3.97918701171875e-1L,
   7.0093852250052539799724507918522711891816E-6L,
   -1.1642216696433999321713012755985118130829E-1L, -2},
  {"y1", y1l, 3.2000000000000000000000000000000001540744E0L,
   3.70697021484375e-1L,
   1.4316956899693924314235987044537888863453E-5L,
   1.9120595686950474169565105767128493632383E-1L, -2},
  {"y1", y1l, 2.6666666666666666666666666666666665382713E0L,
   2.1490478515625e-1L,
   2.3670532079676721084949605457501811641711E-6L,
   3.8729005427236490240034331925211457949310E-1L, -2},
  {"y1", y1l, 2.2857142857142857142857142857142856042326E0L,
   4.5166015625e-2L,
   8.7239712233519705260050662298731987015100E-6L,
   4.9900759601438865416604067629675208716502E-1L, -2},
  {"y1", y1l, 2.0L,
   -1.070404052734375e-1L,
   7.9737324999531116292277225233633125191018E-6L,
   5.6389188842021389304079197886589619161188E-1L, -2},
  {"jnl", NULL, 6.9388939039072283776476979255676269531250E-18L,
   6.9602982143332406209530299018670212642178E-54L,
   2.6551531852207537950481339962774251294400E-59L,
   3.0092655e-36L, -2},
#endif
  {"lgamma", lgammal, 8.0L, 8.525146484375L,
   1.4876690414300165531036347125050759667737E-5L,
   2.0156414779556099965363450527747404656959E0L, 4},
  {"lgamma", lgammal, 0.125L, 2.0194091796875E0L,
   9.1778662963453202905211670995899482809521E-6L,
   -8.3884926632958548678027429230863429642684E0L, 4},
  {"lgamma", lgammal, 0.375L, 8.63067626953125E-1L,
   6.3553175224624050890941340154953324706293E-6L,
   -2.7539990491451395757640192188045680759926E0L, 4},
  {"lgamma", lgammal, 0.625L, 3.608245849609375E-1L,
   4.9105280026811849576858227794878573691202E-6L,
   -1.4527087645765665672107816120233772668729E0L, 4},
  {"lgamma", lgammal, 0.875L, 8.5845947265625E-2L,
   1.2759959709323502365583769487702269719126E-5L,
   -8.0401707154769538232421854974614639758707E-1L, 4},
  {"lgamma", lgammal, 1.0L, 0.0L,
   0.0L, -5.7721566490153286060651209008240239144696E-1L, -4},
  {"lgamma", lgammal, 1.125L, -6.0028076171875E-2L,
   4.8920458354170685941567925698857217805491E-6L,
   -3.8849266329585486780274292308634296426837E-1L, 4},
  {"lgamma", lgammal, 1.375L, -1.17767333984375E-1L,
   1.2063243296225548637966682011495753460784E-5L,
   -8.7332382478472909097352552137901409325952E-2L, 4},
  {"lgamma", lgammal, 1.625L, -1.091766357421875E-1L,
   2.5019853921275340206546744374231564700714E-6L,
   1.4729123542343343278921838797662273312715E-1L, 4},
  {"lgamma", lgammal, 1.875L, -4.76837158203125E-2L,
   1.1030421124200356021962838137727680303452E-5L,
   3.3884007130944747481863859311099645955579E-1L, 4},
  {"lgamma", lgammal, 2.375L, 2.0068359375E-1L,
   1.4866627455841358885180272611091348667235E-5L,
   6.3994034479425436362992017513482586340132E-1L, 4},
  {"lgamma", lgammal, 2.75L, 4.752044677734375E-1L,
   1.0199141499630313102466395428861742242065E-5L,
   8.1890102497543259227787514194472409043081E-1L, 4},
  {"lgamma", lgammal, 3.5L, 1.2009735107421875E0L,
   9.1604886724816021881450712995770238915468E-8L,
   1.1031566406452431872256903336679111259463E0L, 4},
  {"lgamma", lgammal, 4.5L, 2.4537353515625E0L,
   1.2192799422205041425034357161573318235107E-6L,
   1.3888709263595289015114046193821968402320E0L, 4},
  {"lgamma", lgammal, 5.5L, 3.9578094482421875E0L,
   4.5193765287938774008558225909985513044920E-6L,
   1.6110931485817511237336268416044190624542E0L, 4},
  {"lgamma", lgammal, 6.5L, 5.6625518798828125E0L,
   1.0179974329028522112312329543730297511212E-5L,
   1.7929113303999329419154450234226008806361E0L, 4},
  {"lgamma", lgammal, 7.5L, 7.53436279296875E0L,
   1.4437899829551583676324366857670272790220E-6L,
   1.9467574842460867880692911772687547267899E0L, 4},
  {"lgamma", lgammal, 8.5L, 9.54925537109375E0L,
   1.1886207247711737140081127222543124870800E-5L,
   2.0800908175794201214026245106020880601232E0L, 4},
  {"lgamma", lgammal, 9.5L, 1.16893310546875E1L,
   2.3661097684825694425775421725106375736779E-6L,
   2.1977378764029495331673303929550292365938E0L, 4},
  {"lgamma", lgammal, 10.5L, 1.394061279296875E1L,
   1.2426435013633161237887971849479799452805E-5L,
   2.3030010342976863752725935508497660786991E0L, 4},
  {"lgamma", lgammal, 11.5L, 1.62919921875E1L,
   8.2890672413202446037468793783460085279579E-6L,
   2.3982391295357816133678316460878613167943E0L, 4},
  {"lgamma", lgammal, 12.5L, 1.8734344482421875E1L,
   3.0295145707016341244572313978963754081384E-6L,
   2.4851956512749120481504403417400352298378E0L, 4},
  {"lgamma", lgammal, 13.5L, 2.126007080078125E1L,
   5.3554634511414184110022255966073511107125E-6L,
   2.5651956512749120481504403417400352298378E0, 4},
  {"lgamma", lgammal, -0.5L,  1.2655029296875E0L,
   9.1937971453964889457971347059238991475408E-6L,
   3.6489973978576520559023667001244459279636E-2L, 4},
  {"lgamma", lgammal, -1.5L, 8.6004638671875E-1L,
   6.2865773101451093268167035678732715711736E-7L,
   7.0315664064524318722569033366791112594630E-1L, 4},
  {"lgamma", lgammal, -2.5L, -5.6243896484375E-2L,
   1.7998670094932740546990234571587705589745E-7L,
   1.1031566406452431872256903336679111259463E0L, -4},
  {"lgamma", lgammal, -3.5L,-1.30902099609375E0L,
   1.4311100707953639284847917342554315471302E-5L,
   1.3888709263595289015114046193821968402320E0L, -4},
  {"lgamma", lgammal, 1.0e18L, 4.0446531673037733888E19L,
   8.5508840451951888057681732252156677289759E8L,
   4.1446531673892822311823846184318555736736E1, 4},
  {"tgamma", tgammal, 1.0L, 1.0L,
   0.0L, -5.772156649015328606e-1L, 4},
  {"tgamma", tgammal, 2.0L, 1.0L,
   0.0L, 4.2278433509846713939e-1L, 4},
  {"tgamma", tgammal, 3.0L, 2.0L,
   0.0L, 1.845568670196934279L, 4},
  {"tgamma", tgammal, 4.0L, 6.0L,
   0.0L, 7.536706010590802836L, 4},
  {NULL, NULL, 0.0L, 0.0L, 0.0L, 1},
};

/* These take care of extra-precise floating point register problems.  */
static volatile long double volat1;
static volatile long double volat2;


/* Return the next nearest floating point value to X
   in the direction of UPDOWN (+1 or -1).
   (Might fail if X is denormalized.)  */

static long double
nextval (x, updown)
     long double x;
     int updown;
{
  long double m;
  int i;

  volat1 = x;
  m = 0.25L * MACHEPL * volat1 * updown;
  volat2 = volat1 + m;
  if (volat2 != volat1)
    printf ("successor failed\n");

  for (i = 2; i < 10; i++)
    {
      volat2 = volat1 + i * m;
      if (volat1 != volat2)
	return volat2;
    }

  printf ("nextval failed\n");
  return volat1;
}




int
monotll ()
{
  long double (*fun1) (long double);
  int i, j, errs, tests, err_thresh;
  long double x, x0, dy, err;

  errs = 0;
  tests = 0;
  i = 0;

  for (;;)
    {
      /* Function call reference.  */
      fun1 = test1[i].func;
      if (test1[i].name == NULL)
	break;
      /*
      if (fun1 == NULL)
	break;
      */
      /* Function argument.  */
      volat1 = test1[i].arg1;
      /* x0 is the given argument, x scans from slightly below to above x0. */
      x0 = volat1;
      x = volat1;
      for (j = 0; j <= NPTS; j++)
	{
	  /* delta x */
	  volat1 = x - x0;
	  /* delta y */
	  dy = volat1 * test1[i].derivative;
	  /* y + delta y */
	  dy = test1[i].answer2 + dy;
	  volat1 = test1[i].answer1 + dy;
	  /* Run the function under test.  */
	  if (fun1 == NULL)
	    {
#if 0
	      if (! strcmp (test1[i].name, "jnl"))
		volat2 = jnl (3, x);
	      else
#endif
		break;
	    }
	  else
	    volat2 = (*(fun1)) (x);
	  if (volat2 != volat1)
	    {
	      /* Estimate difference between program result
		 and extended precision function value.  */
	      err = volat2 - test1[i].answer1;
	      err = err - dy;
	      /* Compare difference with reporting threshold.  */
	      err_thresh = test1[i].thresh;
	      if (err_thresh >= 0)
		err = err / volat1; /* relative error */
	      else
		{
		  err_thresh = -err_thresh; /* absolute error */
		  /* ...but relative error if function value > 1 */
		  if (fabsl(volat1) > 1.0L)
		    err = err / volat1;
		}
	      if (fabsl (err) > (err_thresh * MACHEPL))
		{
		  printf ("%d %s(%.36Le) = %.36Le, rel err = %.3Le\n",
			  j, test1[i].name, x, volat2, err);
		  errs += 1;
		}
	    }
	  x = nextval (x, 1);
	  tests += 1;
	}

      x = x0;
      x = nextval (x, -1);
      for (j = 1; j < NPTS; j++)
	{
	  volat1 = x - x0;
	  dy = volat1 * test1[i].derivative;
	  dy = test1[i].answer2 + dy;
	  volat1 = test1[i].answer1 + dy;
	  if (fun1 == NULL)
	    {
#if 0
	      if (! strcmp (test1[i].name, "jnl"))
		volat2 = jnl (3, x);
	      else
#endif
		break;
	    }
	  else
	    volat2 = (*(fun1)) (x);
	  if (volat2 != volat1)
	    {
	      err = volat2 - test1[i].answer1;
	      err = err - dy;
	      err_thresh = test1[i].thresh;
	      if (err_thresh >= 0)
		err = err / volat1; /* relative error */
	      else
		{
		  err_thresh = -err_thresh;
		  if (fabsl(volat1) > 1.0L)
		    err = err / volat1;
		}
	      if (fabsl (err) > (err_thresh * MACHEPL))
		{
		  printf ("%d %s(%.36Le) = %.36Le, rel err = %.3Le\n",
			  j, test1[i].name, x, volat2, err);
		  errs += 1;
		}
	    }
	  x = nextval (x, -1);
	  tests += 1;
	}
      i += 1;
    }
  printf ("%d errors in %d tests\n", errs, tests);
  return (errs);
}
#endif	/* LDBL_MANT_DIG == 113 */
