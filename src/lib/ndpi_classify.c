/*
 *
 * Copyright (c) 2016 Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * \file ndpi_classify.c
 *
 * \brief contains the functionality for inline classification
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <ctype.h>
// #include <sys/time.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "ndpi_main.h"
#include "ndpi_classify.h"

/** finds the minimum value between to inputs */
#ifndef min
#define min(a,b)				\
  ({ __typeof__ (a) _a = (a);			\
    __typeof__ (b) _b = (b);			\
    _a < _b ? _a : _b; })
#endif


//bias (1) + w (207)
//const float ndpi_parameters_splt[NUM_PARAMETERS_SPLT_LOGREG] = {
float ndpi_parameters_splt[NUM_PARAMETERS_SPLT_LOGREG] = {
							  -2.088057846500587456e+00, 7.763936238952200239e-05, 4.404309737393306595e-05, -9.467385027293546973e-02,
							  4.348947142638090457e-01, -2.091409170053043390e-04, -5.788902107267982974e-04, 4.481443450852441001e-10,
							  -3.136135459023654537e+00, -1.507730262127600751e+00, -1.204663669965535977e+00, -1.171839254318371104e+00,
							  4.329302247232582057e-01, 8.310653628092458334e+00, 3.299246725156660176e+00, 0.000000000000000000e+00,
							  1.847454931582027254e-02, -1.498024139966201096e+00, -7.660670007653060942e-01, -2.908130300830076731e+00,
							  -1.252564844610269734e+00, -1.910955328742287573e+00, 9.471710980110392697e-01, 2.352302758516665371e+00,
							  2.982269972214651954e+00, 4.280736383314343918e+00, 4.633629909719495288e+00, -2.198052637823726840e+00,
							  -1.150759637168392580e+00, 3.420433363184381292e+00, 1.857878113059351077e-02, -1.559806674919653746e+00,
							  4.197498183183401288e+00, 6.262186949633183453e+00, 1.100694844370524095e+01, 2.778688785515088000e+01,
							  3.679948298336883195e+00, -2.432801394376875592e+00, 5.133442052706843617e-01, 2.181172654073517680e+00,
							  -8.577551729671881731e-01, 7.013844214023315926e-01, 3.138233436228588857e+00, 7.319940508466630247e-01,
							  0.000000000000000000e+00, 3.529209394581482861e+00, 1.464585117707144413e+01, 8.506550226820598359e-01,
							  -9.060397326548508268e-01, 6.787474954688997641e+00, 8.125411068867387954e+00, 4.515740684104064151e+00,
							  5.372135582950940069e+00, 9.210951196799497254e-01, 4.802177410869620466e+00, 2.945445016176073594e+01,
							  1.575032253128311632e+00, -1.355276854364796946e-01, -3.322474764169629502e-01, 3.018397817188666732e+00,
							  1.186503569922195744e+00, 0.000000000000000000e+00, 8.883242370198487503e-01, 7.248276146728496627e+00,
							  0.000000000000000000e+00, 0.000000000000000000e+00, -4.831246718433664711e+00, 6.124136970173365002e-01,
							  4.145693892559814686e-01, 2.683998941637626867e+00, 2.063906603639539039e+00, 2.989801217386735210e+00,
							  2.262965767379551962e-01, 2.240332214649647380e+00, 5.984550782416063086e+00, 4.587011255338186544e+00,
							  1.233118485315272039e+01, 1.115223490909697857e+00, -3.682686422016995476e+00, 6.096498453291562258e-01,
							  1.119275528656461516e+00, 1.377886278915177731e-01, 3.828176805973048324e+00, 0.000000000000000000e+00,
							  0.000000000000000000e+00, 1.442927634029647344e+01, 0.000000000000000000e+00, 5.719118583309401593e-01,
							  1.993632609731877392e-01, 3.047472271520709430e+00, 5.736784864911910198e+00, 6.677826247219391220e+00,
							  6.307175478564531090e+00, 3.150295169417364249e+01, 3.738597740702392258e+00, 1.129754590514236234e+01,
							  6.108506268573830056e+00, 1.605489516792866667e+00, 2.929631990348545489e+00, -2.832543082245212937e-02,
							  1.358286530670594461e+00, 1.655932469853677924e+00, 6.701964773769768513e-01, 2.131182050917533211e+00,
							  2.998351165769753468e+00, 7.772095996358327596e+00, 1.285014785269981141e+00, 4.407334784589962418e+00,
							  1.719858214230612026e+00, -1.012765674651314063e+00, -5.749271123172469133e-01, -3.559614093795681278e+00,
							  -3.073088477387719397e+00, -4.492469521371540431e+00, -3.753286990415885427e+00, -3.219255423324282273e+00,
							  -2.806436518181075090e+00, -2.697305948568419875e+00, -7.879608430851776646e-01, 4.625507221739111330e+00,
							  4.809280703883450414e+00, -3.435194026629848629e+00, -3.218943068168937049e+00, 3.335535704890596698e+00,
							  2.071359212435486263e+00, 4.538992059175040339e+00, -2.770772323566738038e+01, 2.903047708571506735e+00,
							  -4.436143805989154032e+00, -2.647991280011542381e-01, 1.737252348126810064e+00, -4.121989655995259128e+00,
							  3.209709099445720581e-01, 1.012758514896711759e+01, 3.313255624721038295e+00, 4.631467619785444967e+00,
							  7.668642402146534032e+00, 6.780938812710099128e+00, -3.256164342602652972e+00, 6.749565128319576779e-01,
							  0.000000000000000000e+00, -4.407265954524525853e+00, 0.000000000000000000e+00, -3.666522115024547901e+01,
							  -7.886029397826226273e+01, 0.000000000000000000e+00, 0.000000000000000000e+00, -2.261283814517791058e+01,
							  -4.024317426178160240e+00, 3.213063737030031342e-01, 5.079805145796887800e+00, 1.326813226475260343e+00,
							  1.233684078112145643e+00, 8.671852503871454232e+00, -2.041800256066371944e+00, 0.000000000000000000e+00,
							  0.000000000000000000e+00, -1.607347800380474823e+01, -4.430790279223246309e+00, 1.177552465851384511e+00,
							  6.342921220500139512e+00, -2.466913734548706327e-02, 3.451642566010713065e-01, -6.012767168531006234e+00,
							  7.328146570137336724e+00, 7.500088131707050465e+00, 0.000000000000000000e+00, -3.547913249211809017e+01,
							  -3.130964814607208879e+00, 8.247326544297072237e-01, 3.757262485775580418e-01, -2.136528302027558723e+00,
							  -2.631627236037529793e-01, -2.016718799388414141e+01, 0.000000000000000000e+00, 0.000000000000000000e+00,
							  0.000000000000000000e+00, -7.708602132869285528e-01, -2.602868328868111814e+00, 1.435184800833797958e+00,
							  0.000000000000000000e+00, -2.080420864280113413e+00, 1.169498351211070819e+00, -1.798334115637199560e+01,
							  -1.193885252696202670e+01, 0.000000000000000000e+00, 0.000000000000000000e+00, 4.304089297965300709e+00,
							  -3.020893216686394656e+00, -1.234427481614708721e+00, 0.000000000000000000e+00, 1.853340741926325697e+00,
							  -2.686000064995862147e+01, -1.672275139058893600e+01, -2.826268691607605987e+01, 0.000000000000000000e+00,
							  0.000000000000000000e+00, -1.547397429377200817e+00, -4.018181657009961327e+00, -7.289186736637049968e+00,
							  -7.458655219230571731e+00, -9.625538282761622710e+00, -1.103039457077456298e+01, -6.262675161142102809e+01,
							  -9.265912629799268885e+00, -8.961543476816615339e+00, -9.622764435629340696e+00, -1.097978292092879826e+01,
};

//bias (1) + w (207)
//const float ndpi_parameters_bd[NUM_PARAMETERS_BD_LOGREG] = {
float ndpi_parameters_bd[NUM_PARAMETERS_BD_LOGREG] = {
						      -1.678134053325450292e+00, 1.048946534609769413e-04, 9.608725756967682636e-05, -7.515489355100658797e-02,
						      2.089554874872663892e-01, -1.012058874142656513e-04, -2.917652723373885169e-04, 1.087540461196068741e-10,
						      -2.594688448425090055e+00, -2.071803573048482061e+00, -1.399303273236228939e+00, -2.089300736641718004e+00,
						      -8.842347826063630123e-01, 6.476433717022786141e+00, 3.114501282249810377e+00, -2.239127990932460399e+00,
						      -4.667574389646080291e-01, -2.200651610813817438e+00, -1.674926704401964894e+00, -3.894420410398949706e+00,
						      -1.232376502509682004e+00, -2.231027070413975189e+00, 7.691948448668822769e-01, 3.222335181407633531e+00,
						      1.430983188964249919e+00, 2.144317250116257956e+00, 6.596745231472220361e+00, -2.464580889153460852e+00,
						      -1.923337901965658681e+00, 2.910328594745831943e+00, -3.123244869063500073e-01, -1.683345539896562659e+00,
						      3.785795988845424898e+00, 5.235473328290667361e+00, 8.512526402199654285e+00, 1.393475907195251473e+01,
						      1.673386027437856916e+00, -2.910729265724139925e+00, 2.969886703676111184e-01, 1.700051266957717466e+00,
						      -5.472121114836264733e-01, 1.716354591332415469e-01, 3.177884264837486317e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 1.924354871334499062e-01, 6.568439271753665487e+00, 2.102316342451608644e-01,
						      -1.132124603237853355e+00, 7.329625148148498859e+00, 6.606460464951361189e+00, 2.844223241371105271e+00,
						      3.078771172794853683e+00, 0.000000000000000000e+00, 2.656884613648917703e+00, 1.779697712165259205e+01,
						      0.000000000000000000e+00, -3.457017935109325535e-01, 2.157595478838472414e-01, 3.829196175023549031e+00,
						      0.000000000000000000e+00, 1.650776974765602867e-01, 1.357223085191380796e-02, 3.946357663253555081e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, -2.155616432815957495e+00, 8.213633570666911687e-01,
						      1.125480801049912050e-01, 2.684005418659722420e+00, 5.769541257304295900e-01, 1.060883870466023948e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 3.413708974045502664e+00, 2.275281553961784553e+00,
						      5.176725998383044924e+00, 1.019445219242678835e+00, -1.848344450190015698e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 1.491820649409327126e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 9.379741891282449728e+00, 0.000000000000000000e+00, 5.444605374840002510e-01,
						      -9.654403640632221173e-02, 2.642171746731144744e+00, 4.626416118226488905e+00, 3.654642208477139498e+00,
						      3.427412899258296619e+00, 1.490784083593987397e+01, 2.322393214516801141e+00, 6.511453713852694669e+00,
						      6.949721651828602020e+00, 1.186838154505042375e+00, 2.072129970488261197e+00, 0.000000000000000000e+00,
						      1.598928631178261561e+00, 5.926083912988970859e-01, -1.612886287403501873e-01, 9.452951868724716045e-01,
						      2.145707914290207352e+00, 5.391610489831286657e+00, 8.454389313314318866e-01, 2.372736567215404602e+00,
						      -3.130110237826235764e-01, -2.994989290166069740e+00, -2.571950567149417832e+00, -5.018016256298333921e+00,
						      -4.851489154898488643e+00, -7.101788768628541249e+00, -5.227281714666618839e+00, -6.351346048086286444e+00,
						      -4.558191218464671124e+00, -5.293990544168526213e+00, -2.920034449434862345e-01, 5.166915658100844411e+00,
						      4.642130303354632836e+00, -5.246106907306949951e-01, -3.120281208300208498e+00, 1.544764033379846691e+00,
						      0.000000000000000000e+00, 3.721469736246234561e+00, -1.083434721745241625e+01, 2.901590918368040395e+00,
						      -3.602037909234679258e+00, 0.000000000000000000e+00, 2.736307835089097917e+00, -5.037400262764839987e+00,
						      -1.163050013241316849e+00, 6.565863507998260573e+00, 1.872406036485896097e+00, 2.249439295570562880e+00,
						      3.276076277814265136e+00, 5.747730113795930684e+00, -2.084335807954610154e+00, 1.812930768433161921e+00,
						      0.000000000000000000e+00, -4.068875727535363751e+00, -4.509432609364653205e-02, -1.424182063303933710e+01,
						      -1.743400430675688639e+01, 0.000000000000000000e+00, 0.000000000000000000e+00, -8.986019040369217947e+00,
						      -2.005955598483518898e+00, 1.514163405869717538e+00, 4.060752357984299010e+00, 1.405971170124569403e+00,
						      1.383171915541985708e+00, 4.654452090729912506e+00, -3.395023560174311950e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, -8.562968788250293173e+00, -1.939561462845156514e+00, 2.627499899415196793e+00,
						      4.949794698120698833e+00, 4.355655772643094448e-01, 0.000000000000000000e+00, -1.055190553626396577e+00,
						      4.757318838337171840e+00, 3.966536148163406938e+00, 0.000000000000000000e+00, -1.190662117721104352e+01,
						      -1.673945042186458121e+00, 0.000000000000000000e+00, -1.203943763219820356e-02, -1.411827841131889194e+00,
						      -7.623501643009024109e-01, -6.774873775798392117e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, -1.755294779557688090e+00, 1.542887322103192238e+00,
						      0.000000000000000000e+00, -8.228978371972577310e-01, 0.000000000000000000e+00, -5.379142925264499553e+00,
						      -1.144060263986041326e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 4.731108583634047626e+00,
						      -1.569393147397664556e+00, -3.449886418134247568e-01, 0.000000000000000000e+00, 1.658412661295906920e+00,
						      -5.077151059809188460e+00, -7.326467579034271260e+00, -1.190177296658179840e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, -1.914781807241187739e+00, -5.438446604150855457e+00,
						      -5.988893208768400811e+00, -7.886849112491050029e+00, -9.355574940159534947e+00, -1.682361325340106006e+01,
						      -7.609538696398503888e+00, -7.363350786768400269e+00, -7.366039984795356155e+00, -7.051111570136543882e+00,
						      2.337391373249395610e+00, -4.374845402801011574e+01, -3.610863365629191080e+00, 7.684297617701028571e+01,
						      2.162851395732025139e+01, 1.066280518306870562e+01, 8.109257308306457901e+01, 5.149561395669890906e+00,
						      0.000000000000000000e+00, 3.219993054481156136e+00, 0.000000000000000000e+00, 2.093519725422254396e+01,
						      -5.225298528278367272e+00, 0.000000000000000000e+00, 2.159597932230871820e+00, -5.205637201784965384e+01,
						      1.601979388461561982e+01, 6.945290207097973401e+00, 8.036724740759808583e-01, 4.712266457087280536e+00,
						      2.146353485778652370e+01, 3.470089369007970248e+01, 9.468591086256607170e+00, 9.760488656497257054e-01,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 9.008837970422939323e-01,
						      0.000000000000000000e+00, 1.462843531299845168e+01, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      -1.179406942091425847e+01, 0.000000000000000000e+00, 1.642473653464513816e+01, 1.387228776263151175e+01,
						      0.000000000000000000e+00, 1.613129141280310108e+01, 0.000000000000000000e+00, -1.077318890268341045e+00,
						      4.189407459072477802e-01, 0.000000000000000000e+00, -1.570052145651456899e+00, 0.000000000000000000e+00,
						      1.120834605828141939e+01, 4.286417457736029490e+01, 0.000000000000000000e+00, 2.938378293327098945e+01,
						      1.194087082487160956e+01, 0.000000000000000000e+00, -9.951431855637998813e-02, 3.844291513997798448e-01,
						      2.362333099868798669e+01, -1.002532136112976957e+01, 2.427817537309562823e+01, 0.000000000000000000e+00,
						      1.076329692188489773e+01, 1.760895870067486157e+00, 2.080295785135324849e+01, -4.335217053626006134e+01,
						      -6.272369476984676062e-01, 5.165768790797590881e+00, -4.507215926635629311e-01, 0.000000000000000000e+00,
						      -4.242472062530233679e+00, -4.931831554080153168e+00, -2.806203935735193777e+00, -2.670377941558885126e+01,
						      0.000000000000000000e+00, -2.124688439238133242e+01, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      2.452415244698852970e+00, -1.173727222080745092e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      -1.458125295680756039e+01, -1.757703406512062827e+01, 0.000000000000000000e+00, 3.943626521423988951e+00,
						      0.000000000000000000e+00, -4.006095410470026152e+00, 1.727171067402430538e+01, -3.412620901789366457e+01,
						      0.000000000000000000e+00, 1.760073934312834254e+01, 3.266082201875645552e+01, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 1.514535424913179362e+01, 0.000000000000000000e+00,
						      0.000000000000000000e+00, -3.100487758075622935e-01, 0.000000000000000000e+00, 2.387863228159451978e+01,
						      1.237098847411416891e+01, 1.154430573879687560e-02, 7.976366278729441817e+00, 0.000000000000000000e+00,
						      -6.296727640787388447e-01, 1.406230674131906255e+01, 1.430275589872723430e+01, -2.231764570537816184e+00,
						      0.000000000000000000e+00, 5.003869692542436631e+00, 0.000000000000000000e+00, -5.482127427587509594e+00,
						      -8.830547931126154992e+00, -5.376776036224484301e+01, -2.918517871695104304e+01, -1.009022417771788049e+01,
						      -4.811775051355994037e+00, -1.188016976215758547e+01, -2.055483647266791536e+01, -2.482333959706277327e+01,
						      -1.048392515070836950e+01, -3.837352144714887459e+01, 0.000000000000000000e+00, -9.298440675063780247e+00,
						      0.000000000000000000e+00, 3.584086297861655890e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 1.184271790014085113e+00,
						      1.594266439891793219e+01, 0.000000000000000000e+00, 8.473235161049382569e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 6.748879951595517568e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, -1.057534737660506430e+01, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, -3.179879192807419841e+01, 0.000000000000000000e+00, 5.000324879565139824e+00,
						      0.000000000000000000e+00, 1.229183419446936654e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      4.127983063177185663e+00, 6.616705680943091750e+00, 5.848245769217652601e+00, -1.818944631334333550e+01,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      2.694838778746875274e+00, 0.000000000000000000e+00, 1.463145767737777625e+01, -4.924734438569850603e+00,
						      0.000000000000000000e+00, 1.877377621310543088e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      1.971941442729244764e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 1.732809836566829187e+00, 2.700285877421266534e+01,
						      2.915978562591383216e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, -6.999629705176019456e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 1.089611710258455268e+01,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      2.121018958070171934e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      -7.416250358067024706e+00, -1.263327458973565065e+01, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 2.241612733384156897e+01,
						      0.000000000000000000e+00, 8.607688079645482659e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 1.750217629228628269e+01, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, -1.957769005108392690e+01, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, -3.242393079195928784e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 1.348338590741638932e+01, 0.000000000000000000e+00,
						      -2.000312276678208392e-02, -7.776608146776987640e-01, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, -5.387825733845168941e+00, 0.000000000000000000e+00, 2.153516224136292934e+01,
						      0.000000000000000000e+00, 0.000000000000000000e+00, -9.635140703414636576e+00, 2.603288107669730511e+00,
};

/**
 * \fn void ndpi_merge_splt_arrays (const uint16_t *pkt_len, const struct timeval *pkt_time,
 const uint16_t *pkt_len_twin, const struct timeval *pkt_time_twin,
 struct timeval start_time, struct timeval start_time_twin,
 uint16_t s_idx, uint16_t r_idx,
 uint16_t *merged_lens, uint16_t *merged_times,
 uint32_t max_num_pkt_len, uint32_t max_merged_num_pkts)
 * \param pkt_len length of the packet
 * \param pkt_time time of the packet
 * \param pkt_len_twin length of the twin packet
 * \param pkt_time_twin time of the twin packet
 * \param start_time start time
 * \param start_time_twin start time of twin
 * \param s_idx s index in the merge
 * \param r_idx r index in the merge
 * \param merged_lens length of the merge
 * \param merged_times time of the merge
 * \param max_merged_num_pkts number of packets merged
 * \return none
 */
void
ndpi_merge_splt_arrays (const uint16_t *pkt_len, const struct timeval *pkt_time,
                        const uint16_t *pkt_len_twin, const struct timeval *pkt_time_twin,
                        struct timeval start_time, struct timeval start_time_twin,
                        uint16_t s_idx, uint16_t r_idx,
                        uint16_t *merged_lens, uint16_t *merged_times)
{
  int s,r;
  struct timeval ts_start = { 0, 0 }; /* initialize to avoid spurious warnings */
  struct timeval tmp, tmp_r;
  struct timeval start_m;

  if(r_idx + s_idx == 0) {
    return ;
  } else if(r_idx == 0) {
    ts_start = pkt_time[0];
    tmp = pkt_time[0];
    ndpi_timer_sub(&tmp, &start_time, &start_m);
  } else if(s_idx == 0) {
    ts_start = pkt_time_twin[0];
    tmp = pkt_time_twin[0];
    ndpi_timer_sub(&tmp, &start_time_twin, &start_m);
  } else {
    if(ndpi_timer_lt(&start_time, &start_time_twin)) {
      ts_start = pkt_time[0];
      tmp = pkt_time[0];
      ndpi_timer_sub(&tmp, &start_time, &start_m);
    } else {
      //      ts_start = pkt_time_twin[0];
      tmp = pkt_time_twin[0];
      ndpi_timer_sub(&tmp, &start_time_twin, &start_m);
    }
  }
  s = r = 0;
  while ((s < s_idx) || (r < r_idx)) {
    if(s >= s_idx) {
      merged_lens[s+r] = pkt_len_twin[r];
      tmp = pkt_time_twin[r];
      ndpi_timer_sub(&tmp, &ts_start, &tmp_r);
      merged_times[s+r] = ndpi_timeval_to_milliseconds(tmp_r);
      if(merged_times[s+r] == 0)
	merged_times[s+r] = ndpi_timeval_to_microseconds(tmp_r);
      ts_start = tmp;
      r++;
    } else if(r >= r_idx) {
      merged_lens[s+r] = pkt_len[s];
      tmp = pkt_time[s];
      ndpi_timer_sub(&tmp, &ts_start, &tmp_r);
      merged_times[s+r] = ndpi_timeval_to_milliseconds(tmp_r);
      if(merged_times[s+r] == 0)
	merged_times[s+r] = ndpi_timeval_to_microseconds(tmp_r);
      ts_start = tmp;
      s++;
    } else {
      if(ndpi_timer_lt(&pkt_time[s], &pkt_time_twin[r])) {
	merged_lens[s+r] = pkt_len[s];
	tmp = pkt_time[s];
	ndpi_timer_sub(&tmp, &ts_start, &tmp_r);
	merged_times[s+r] = ndpi_timeval_to_milliseconds(tmp_r);
	if(merged_times[s+r] == 0)
	  merged_times[s+r] = ndpi_timeval_to_microseconds(tmp_r);
	ts_start = tmp;
	s++;
      } else {
	merged_lens[s+r] = pkt_len_twin[r];
	tmp = pkt_time_twin[r];
	ndpi_timer_sub(&tmp, &ts_start, &tmp_r);
	merged_times[s+r] = ndpi_timeval_to_milliseconds(tmp_r);
	if(merged_times[s+r] == 0)
	  merged_times[s+r] = ndpi_timeval_to_microseconds(tmp_r);
	ts_start = tmp;
	r++;
      }
    }
  }
  merged_times[0] = ndpi_timeval_to_milliseconds(start_m);
  if(merged_times[0] == 0)
    merged_times[0] = ndpi_timeval_to_microseconds(start_m);
}

/* transform lens array to Markov chain */
static void
ndpi_get_mc_rep_lens (uint16_t *lens, float *length_mc, uint16_t num_packets)
{
  float row_sum;
  int prev_packet_size = 0;
  int cur_packet_size = 0;
  int i, j;

  for (i = 0; i < MC_BINS_LEN*MC_BINS_LEN; i++) { // init to 0
    length_mc[i] = 0.0;
  }

  if(num_packets == 0) {
    // nothing to do
  } else if(num_packets == 1) {
    cur_packet_size = (int)min(lens[0]/(float)MC_BIN_SIZE_LEN,(uint16_t)MC_BINS_LEN-1);
    length_mc[cur_packet_size + cur_packet_size*MC_BINS_LEN] = 1.0;
  } else {
    for (i = 1; i < num_packets; i++) {
      prev_packet_size = (int)min((uint16_t)(lens[i-1]/(float)MC_BIN_SIZE_LEN),(uint16_t)MC_BINS_LEN-1);
      cur_packet_size = (int)min((uint16_t)(lens[i]/(float)MC_BIN_SIZE_LEN),(uint16_t)MC_BINS_LEN-1);
      length_mc[prev_packet_size*MC_BINS_LEN + cur_packet_size] += 1.0;
    }
    // normalize rows of Markov chain
    for (i = 0; i < MC_BINS_LEN; i++) {
      // find sum
      row_sum = 0.0;
      for (j = 0; j < MC_BINS_LEN; j++) {
	row_sum += length_mc[i*MC_BINS_LEN+j];
      }
      if(row_sum != 0.0) {
	for (j = 0; j < MC_BINS_LEN; j++) {
	  length_mc[i*MC_BINS_LEN+j] /= row_sum;
	}
      }
    }
  }
}

/* transform times array to Markov chain */
void
ndpi_get_mc_rep_times (uint16_t *times, float *time_mc, uint16_t num_packets)
{
  float row_sum;
  int prev_packet_time = 0;
  int cur_packet_time = 0;
  int i, j;

  for (i = 0; i < MC_BINS_TIME*MC_BINS_TIME; i++) { // init to 0
    time_mc[i] = 0.0;
  }
  if(num_packets == 0) {
    // nothing to do
  } else if(num_packets == 1) {
    cur_packet_time = (int)min(times[0]/(float)MC_BIN_SIZE_TIME,(uint16_t)MC_BINS_TIME-1);
    time_mc[cur_packet_time + cur_packet_time*MC_BINS_TIME] = 1.0;
  } else {
    for (i = 1; i < num_packets; i++) {
      prev_packet_time = (int)min((uint16_t)(times[i-1]/(float)MC_BIN_SIZE_TIME),(uint16_t)MC_BINS_TIME-1);
      cur_packet_time = (int)min((uint16_t)(times[i]/(float)MC_BIN_SIZE_TIME),(uint16_t)MC_BINS_TIME-1);
      time_mc[prev_packet_time*MC_BINS_TIME + cur_packet_time] += 1.0;
    }
    // normalize rows of Markov chain
    for (i = 0; i < MC_BINS_TIME; i++) {
      // find sum
      row_sum = 0.0;
      for (j = 0; j < MC_BINS_TIME; j++) {
	row_sum += time_mc[i*MC_BINS_TIME+j];
      }
      if(row_sum != 0.0) {
	for (j = 0; j < MC_BINS_TIME; j++) {
	  time_mc[i*MC_BINS_TIME+j] /= row_sum;
	}
      }
    }
  }
}

/**
 * \fn float classify (const unsigned short *pkt_len, const struct timeval *pkt_time,
 const unsigned short *pkt_len_twin, const struct timeval *pkt_time_twin,
 struct timeval start_time, struct timeval start_time_twin, uint32_t max_num_pkt_len,
 uint16_t sp, uint16_t dp, uint32_t op, uint32_t ip, uint32_t np_o, uint32_t np_i,
 uint32_t ob, uint32_t ib, uint16_t use_bd, const uint32_t *bd, const uint32_t *bd_t)
 * \param pkt_len length of the packet
 * \param pkt_time time of the packet
 * \param pkt_len_twin length of the packet twin
 * \param pkt_time_twin time of the packet twin
 * \param start_time start time
 * \param start_time_twin start time of the twin
 * \param max_num_pkt_len maximum len of number of packets
 * \param sp
 * \param dp
 * \param op
 * \param ip
 * \param np_o
 * \param np_i
 * \param ob
 * \param ib
 * \param use_bd
 * \param *bd pointer to bd
 * \param *bd_t pointer to bd type
 * \return float score
 */
float
ndpi_classify (const unsigned short *pkt_len, const struct timeval *pkt_time,
               const unsigned short *pkt_len_twin, const struct timeval *pkt_time_twin,
               struct timeval start_time, struct timeval start_time_twin, uint32_t max_num_pkt_len,
               uint16_t sp, uint16_t dp, uint32_t op, uint32_t ip, uint32_t np_o, uint32_t np_i,
               uint32_t ob, uint32_t ib, uint16_t use_bd, const uint32_t *bd, const uint32_t *bd_t)
{

  float features[NUM_PARAMETERS_BD_LOGREG] = {1.0};
  float mc_lens[MC_BINS_LEN*MC_BINS_LEN];
  float mc_times[MC_BINS_TIME*MC_BINS_TIME];
  uint32_t i;
  float score = 0.0;

  uint32_t op_n = min(np_o, max_num_pkt_len);
  uint32_t ip_n = min(np_i, max_num_pkt_len);
  uint16_t *merged_lens = NULL;
  uint16_t *merged_times = NULL;

  for (i = 1; i < NUM_PARAMETERS_BD_LOGREG; i++) {
    features[i] = 0.0;
  }

  merged_lens = ndpi_calloc(1, sizeof(uint16_t)*(op_n + ip_n));
  merged_times = ndpi_calloc(1, sizeof(uint16_t)*(op_n + ip_n));

  if(!merged_lens || !merged_times) {
    ndpi_free(merged_lens);
    ndpi_free(merged_times);
    return(score);
  }

  // fill out meta data
  features[1] = (float)dp; // destination port
  features[2] = (float)sp; // source port
  features[3] = (float)ip; // inbound packets
  features[4] = (float)op; // outbound packets
  features[5] = (float)ib; // inbound bytes
  features[6] = (float)ob; // outbound bytes
  features[7] = 0.0;// skipping 7 until we process the pkt_time arrays

  // find the raw features
  ndpi_merge_splt_arrays(pkt_len, pkt_time, pkt_len_twin, pkt_time_twin, start_time, start_time_twin, op_n, ip_n,
			 merged_lens, merged_times);

  // find new duration
  for (i = 0; i < op_n+ip_n; i++) {
    features[7] += (float)merged_times[i];
  }

  // get the Markov chain representation for the lengths
  ndpi_get_mc_rep_lens(merged_lens, mc_lens, op_n+ip_n);

  // get the Markov chain representation for the times
  ndpi_get_mc_rep_times(merged_times, mc_times, op_n+ip_n);

  // fill out lens/times in feature vector
  for (i = 0; i < MC_BINS_LEN*MC_BINS_LEN; i++) {
    features[i+8] = mc_lens[i]; // lengths
  }
  for (i = 0; i < MC_BINS_TIME*MC_BINS_TIME; i++) {
    features[i+8+MC_BINS_LEN*MC_BINS_LEN] = mc_times[i]; // times
  }

  // fill out byte distribution features
  if(ob+ib > 100 && use_bd) {
    for (i = 0; i < NUM_BD_VALUES; i++) {
      if(pkt_len_twin != NULL) {
	features[i+8+MC_BINS_LEN*MC_BINS_LEN+MC_BINS_TIME*MC_BINS_TIME] = (bd[i]+bd_t[i])/((float)(ob+ib));
      } else {
	features[i+8+MC_BINS_LEN*MC_BINS_LEN+MC_BINS_TIME*MC_BINS_TIME] = bd[i]/((float)(ob));
      }
    }

    score = ndpi_parameters_bd[0];
    for (i = 1; i < NUM_PARAMETERS_BD_LOGREG; i++) {
      score += features[i]*ndpi_parameters_bd[i];
    }
  } else {
    for (i = 0; i < NUM_PARAMETERS_SPLT_LOGREG; i++) {
      score += features[i]*ndpi_parameters_splt[i];
    }
  }

  score = min(-score,500.0); // check b/c overflow

  ndpi_free(merged_lens);
  ndpi_free(merged_times);

  return 1.0/(1.0+exp(score));
}

/**
 * \fn void update_params (char *splt_params, char *bd_params)
 * \brief if a user supplies new parameter files, update parameters splt/bd
 * \param param_type type of new parameters to update
 * \param params file name with new parameters
 * \reutrn none
 */
void
ndpi_update_params (classifier_type_codes_t param_type, const char *param_file)
{
  float param;
  FILE *fp;
  int count = 0;

  switch (param_type) {
  case (SPLT_PARAM_TYPE):
    count = 0;
    fp = fopen(param_file,"r");
    if(fp != NULL) {
      while (fscanf(fp, "%f", &param) != EOF) {
	ndpi_parameters_splt[count] = param;
	count++;
	if(count >= NUM_PARAMETERS_SPLT_LOGREG) {
	  break;
	}
      }
      fclose(fp);
    }
    break;

  case (BD_PARAM_TYPE):
    count = 0;
    fp = fopen(param_file,"r");
    if(fp != NULL) {
      while (fscanf(fp, "%f", &param) != EOF) {
	ndpi_parameters_bd[count] = param;
	count++;
	if(count >= NUM_PARAMETERS_BD_LOGREG) {
	  break;
	}
      }
      fclose(fp);
    }
    break;

  default:
    printf("error: unknown paramerter type (%d)", param_type);
    break;
  }
}

/* *********************************************************************
 * ---------------------------------------------------------------------
 *                      Time functions
 * For portability and static analysis, we define our own timer
 * comparison functions (rather than use non-standard
 * timercmp/timersub macros)
 * ---------------------------------------------------------------------
 * *********************************************************************
 */

/**
 * \brief Compare two times to see if they are equal
 * \param a First time value
 * \param b Second time value
 * \return 1 if equal, 0 otherwise
 */
unsigned int
ndpi_timer_eq(const struct timeval *a,
              const struct timeval *b)
{
  if(a->tv_sec == b->tv_sec && a->tv_usec == b->tv_usec) {
    return 1;
  }

  return 0;
}

unsigned int
ndpi_timer_lt(const struct timeval *a,
              const struct timeval *b)
{
  return (a->tv_sec == b->tv_sec) ?
    (a->tv_usec < b->tv_usec):(a->tv_sec < b->tv_sec);
}

/**
 * \brief Calculate the difference betwen two times (result = a - b)
 * \param a First time value
 * \param b Second time value
 * \param result The difference between the two time values
 * \return none
 */
void
ndpi_timer_sub(const struct timeval *a,
               const struct timeval *b,
               struct timeval *result)
{
  result->tv_sec = a->tv_sec - b->tv_sec;
  result->tv_usec = a->tv_usec - b->tv_usec;
  if(result->tv_usec < 0) {
    --result->tv_sec;
    result->tv_usec += 1000000;
  }
}

/**
 * \brief Zeroize a timeval.
 * \param a Timeval to zero out
 * \return none
 */
void
ndpi_timer_clear(struct timeval *a)
{
  a->tv_sec = a->tv_usec = 0;
}

/**
 * \brief Calculate the milliseconds representation of a timeval.
 * \param ts Timeval
 * \return unsigned int - Milliseconds
 */
unsigned int
ndpi_timeval_to_milliseconds(struct timeval ts)
{
  unsigned int result = ts.tv_usec / 1000 + ts.tv_sec * 1000;
  return result;
}

/**
 * \brief Calculate the microseconds representation of a timeval.
 * \param ts Timeval
 * \return unsigned int - Milliseconds
 */
unsigned int
ndpi_timeval_to_microseconds(struct timeval ts)
{
  unsigned int result = ts.tv_usec + ts.tv_sec * 1000 * 1000;
  return result;
}

void
ndpi_log_timestamp(char *log_ts, uint32_t log_ts_len)
{
  struct timeval tv;
  time_t nowtime;
  struct tm nowtm_r;
  char tmbuf[NDPI_TIMESTAMP_LEN];

  gettimeofday(&tv, NULL);
  nowtime = tv.tv_sec;
  localtime_r(&nowtime, &nowtm_r);
  strftime(tmbuf, NDPI_TIMESTAMP_LEN, "%H:%M:%S", &nowtm_r);
  snprintf(log_ts, log_ts_len, "%s.%06ld", tmbuf, (long)tv.tv_usec);
}
