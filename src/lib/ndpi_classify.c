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
#ifdef HAVE_CONFIG_H
#include "ndpi_config.h"
#endif

#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "ndpi_main.h"
#include "ndpi_classify.h"

/** finds the minimum value between to inputs */
#define min(a,b) \
    ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
       _a < _b ? _a : _b; })

//bias (1) + w (207)
//const float ndpi_parameters_splt[NUM_PARAMETERS_SPLT_LOGREG] = {
float ndpi_parameters_splt[NUM_PARAMETERS_SPLT_LOGREG] = {
   1.870162393265777379e+00, -4.795306993214020408e-05, -1.734180056229888626e-04, -6.750871045910851378e-04,
   5.175991233904169049e-04,  3.526042198693187802e-07, -2.903366739676974950e-07, -1.415422572109461820e-06,
  -1.771571627605233568e+00,  1.620550564201104216e+00, -4.612754771764762118e-01,  3.239944708329216994e+00,
   2.798317033823678024e+00,  0.000000000000000000e+00,  6.076539623210191365e+00,  3.308503132975965322e+00,
  -1.092831892216604983e-01,  2.982742154817296765e+00,  1.660969487778582554e+00, -3.456805843507989584e-01,
   1.348166013591903800e+00,  2.574204101170268211e-01,  2.610145601469008980e+00,  1.020576625389262970e+00,
   3.671704233284687646e+00,  6.443945529005814521e-01,  2.252762512697924647e-03,  2.204985803678578549e+00,
  -2.175241664145967091e-01, -1.141779409733734239e-03, -4.170326358555080049e+00, -6.042082896847342788e-01,
   6.081676509559893473e-01,  1.067078220396491028e+00,  3.836704027854674903e-01,  0.000000000000000000e+00,
   2.146120236132928460e-02,  2.432303290345616098e+00, -2.103340262991825860e+00, -1.744126902195192397e+00,
  -2.623163496699073338e+00, -3.407875120566610239e+00, -7.964525551010913640e-01, -1.404640840577571437e+00,
   0.000000000000000000e+00,  0.000000000000000000e+00,  1.880185666666627593e-04,  1.282810736369378146e+00,
  -9.641782614904219617e-01,  4.403448314292253141e-01, -3.657774135738374455e-02,  0.000000000000000000e+00,
  -5.459785394047789175e-02,  0.000000000000000000e+00, -1.282088906132429429e+00,  4.860766361538500224e-02,
  -2.169499256433678802e+00,  4.022086644863120397e-01, -4.914517759289173116e-01, -7.589910385869531595e-01,
   0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00, -8.666757574333044944e-01,
   0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  1.311256230786839394e+00,
  -1.914518488914755068e+00,  1.511887239039312325e+00,  2.178209608648221440e+00, -7.023826963231178944e-01,
   0.000000000000000000e+00,  2.007745367392351800e-03, -1.741067164349403007e-01, -8.226617550716192051e-02,
  -3.117883014105701456e+00,  6.628843265383883576e-01, -2.160748016600245514e+00, -1.405593258704527670e+00,
   1.183206385957070061e+00,  2.757013165261792964e-01,  0.000000000000000000e+00,  0.000000000000000000e+00,
   0.000000000000000000e+00, -1.811005099043709210e+00, -8.455596144009722703e-01,  1.001251761183534761e+00,
  -3.939531953397222841e-01,  1.993035329450950854e+00, -1.019523996210594863e+00, -1.755881638655008015e-01,
  -1.787388667240087603e+00, -2.430688550462867248e-01,  0.000000000000000000e+00, -1.884287953600421561e+00,
  -2.751870090435341254e+00,  1.697458788143338504e+00,  1.849679594159958553e-03,  4.943355128829073908e-01,
   7.369008876756165671e-01,  4.693987613154877003e+00,  3.064798194276571741e-01,  5.387093625046185386e-01,
   0.000000000000000000e+00,  0.000000000000000000e+00,  3.624061495761899732e+00,  3.074260971046838264e-01,
  -1.431368135826769805e+00,  6.994209180148978078e-01,  1.790376540283850959e+00,  1.524331645466284968e+00,
   1.358206060175735086e+00,  1.467425790557983944e+00,  1.186415624035605187e+00,  5.323820984869050976e-01,
   8.591955162076543237e-03,  3.118816279950378800e-01, -4.062663013982938942e-01,  2.242707735666635838e+00,
   7.686176932110666549e-01, -1.560810210584786528e-01,  3.540092084282713825e-01,  0.000000000000000000e+00,
   3.097791434293225565e-01,  0.000000000000000000e+00,  0.000000000000000000e+00, -6.986278186857963757e-01,
  -7.517062056086308564e-02,  7.074462217191725966e-01,  2.652408529563320627e+00,  2.147183236174156074e-01,
   0.000000000000000000e+00, -5.440998469665543347e-01, -4.689480062559393640e-03,  0.000000000000000000e+00,
   0.000000000000000000e+00, -1.086404167506188401e+00,  2.630806090789038487e-01, -7.025803998688389118e-01,
   0.000000000000000000e+00,  3.643784401628049618e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  -2.302902226543305508e-01,  0.000000000000000000e+00,  0.000000000000000000e+00, -1.189427790184047318e+00,
  -1.628347806351332916e-01,  1.811447446865056266e-01, -1.013719736818966766e+00,  0.000000000000000000e+00,
   2.160057499014520488e+00,  5.515077573228228669e-01,  2.124699422003203608e+00,  0.000000000000000000e+00,
   0.000000000000000000e+00, -7.125921670169992339e-01,  1.539140748884923991e-02,  8.977156480543774242e-02,
  -1.449316192295113881e+00, -5.367207427320878910e-03,  7.097016086830079118e-01,  1.787774315099208255e+00,
   1.005405396661134043e+00,  1.444517882048796054e+00,  0.000000000000000000e+00, -1.009699404577948600e+00,
  -1.079157463961748942e+00, -2.360021607239124741e-01, -1.267330554215283733e+00,  0.000000000000000000e+00,
   0.000000000000000000e+00,  0.000000000000000000e+00,  6.230706551651569169e-01,  0.000000000000000000e+00,
   0.000000000000000000e+00, -2.698683840438712789e+00, -2.747165944141573002e-01, -4.768283073662182847e-01,
   0.000000000000000000e+00,  0.000000000000000000e+00, -1.146728572781320565e+00,  0.000000000000000000e+00,
   0.000000000000000000e+00, -1.032915777657712614e-01,  0.000000000000000000e+00, -1.599571851202367112e+00,
  -7.161771625083027670e-01,  0.000000000000000000e+00, -6.673724254887420937e-01,  0.000000000000000000e+00,
   0.000000000000000000e+00,  6.565789901111966920e-01, -1.350289421277870661e+00,  0.000000000000000000e+00,
  -2.540557809308654491e-01, -2.686275845542446028e+00,  5.361226810123980169e-01,  1.934634164672687645e-02,
   1.299889006228968115e-02,  6.711304002369271604e-01,  1.343899312004804392e+00,  1.279831653805828973e+00,
   5.859059243312456644e-01,  0.000000000000000000e+00,  2.700307766027922884e-01,  2.036695317557343010e+00
};

//bias (1) + w (207)
//const float ndpi_parameters_bd[NUM_PARAMETERS_BD_LOGREG] = {
float ndpi_parameters_bd[NUM_PARAMETERS_BD_LOGREG] = {
 -2.953121634313102817e-01, -9.305965891856329863e-05, -1.604178587753208403e-04, -8.663508397764218205e-05,
  3.181501593122275080e-05,  4.869393011205743958e-08, -2.904473357729938132e-09, -1.074435511920153463e-08,
 -2.170603991277066491e+00,  6.744305938858414784e-01,  3.953560850413735395e-01,  1.361925254316559641e+00,
  1.157162016392975223e+00,  0.000000000000000000e+00,  5.716702917241568649e+00,  1.141217827469380719e+00,
  1.167390224134238347e-01,  1.735679328274153610e+00,  1.859512740862381497e+00,  4.883258615168795114e-01,
  1.694259125977817693e+00,  0.000000000000000000e+00,  5.554839579235824054e-01,  0.000000000000000000e+00,
  1.345735088930616108e+00,  0.000000000000000000e+00, -2.971613171619579274e-01,  1.047454429359179873e+00,
  9.399973694675579639e-01,  7.598746535296537763e-01, -2.270823795620748431e+00, -1.642785702691181016e-01,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
 -2.238819520252720796e+00,  1.320309301722541573e+00, -1.178170517074989210e+00, -5.248901176332601004e-01,
 -1.526086287972392652e+00, -1.448285835686268452e+00, -8.209891928947434803e-01,  0.000000000000000000e+00,
 -1.253512931392381846e+00, -2.448957234640304903e-01, -5.824079377648076067e-02,  1.071684992928929603e+00,
 -3.143934817584292940e-01,  0.000000000000000000e+00, -1.299533530342349696e-01, -1.253665208636307038e-01,
 -3.741714538964039938e-01,  0.000000000000000000e+00, -1.372041577445057836e+00,  0.000000000000000000e+00,
 -1.917828430687468666e+00, -1.548156526634417163e-01,  5.069051123254834090e-01, -1.579024137221134161e-01,
 -1.048766310256059320e-01, -5.027575687530223547e-01,  0.000000000000000000e+00, -5.343127955429831655e-01,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  5.661515321448501448e-01,
 -9.602468971260632591e-01,  1.234839834610549136e+00,  2.568742974036687610e+00, -1.208604146468972962e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
 -1.243861991675339285e+00,  1.460993074682226112e-01, -9.749410166410891199e-01, -4.734754507582912275e-01,
  1.215455435501987813e-01, -2.751667313316082386e-01, -3.432376587556000835e-01,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00, -3.761783741549818982e-01,  2.086986851763828199e-01,
  0.000000000000000000e+00,  2.649701266176835102e+00, -1.038834923035417024e+00, -1.122672461489231804e-02,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00, -9.799954015364449322e-01,
 -1.991974099640831497e+00,  1.018427492696482473e+00, -4.088041953740855772e-01,  0.000000000000000000e+00,
  0.000000000000000000e+00,  4.487847808661091342e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  1.697146906018167645e+00,  1.107723995708555842e+00,
 -2.057318347123237301e-01, -2.368883723763162974e-01,  4.579837206658370907e-01, -7.570289077756563456e-01,
  8.983818467769307814e-01,  3.537910300939053898e-01,  1.626458397365482922e+00, -3.300836572181266044e-03,
  4.462742143753217761e-02, -1.060184844754213929e-01,  7.810440381838920088e-01,  1.108448216567373246e+00,
  4.128252619360664455e-01, -1.297851442719749060e-01,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  5.652218691992449973e-02,
  7.903490726090427465e-01,  8.820592605559850197e-02,  2.826173435847224802e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00, -1.865231101602988772e-01,  3.218796325953430237e-01,  0.000000000000000000e+00,
  0.000000000000000000e+00,  1.550652675020544047e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00, -9.513272705900219228e-02, -3.196580534765853243e-01,  0.000000000000000000e+00,
  1.082802500845317706e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  7.235666749441156398e-01,  6.118502361754621921e-01, -1.185111512789118055e-01,
  0.000000000000000000e+00,  0.000000000000000000e+00,  1.050418002990574778e-01,  1.551405135682879077e+00,
  2.961761913622366293e+00,  1.901323616697461638e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
 -1.332435043211266379e-01,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00, -1.255550783719393104e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
 -2.922246847407067860e-01, -5.280391235416594942e-01,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  1.844123585821513034e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00, -7.628573689172206684e-01,  8.523051946436761561e-01, -5.592366398773165326e-01,
 -3.669000025853382807e-01, -5.937559516814655547e-01,  1.445088862911829697e-01,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00, -4.041970430267569636e-01,
  2.792928239224993003e+00, -2.814321020845482835e+01,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  3.678601293162953589e-01,  0.000000000000000000e+00,  0.000000000000000000e+00,
  6.131733342900005379e-01,  7.184288961660294515e-01,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  3.231331452948340566e-01,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  2.409261496800221725e+00,
  0.000000000000000000e+00,  2.548575142888419798e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  2.458286773678776349e+00,  0.000000000000000000e+00,
  1.319538118247471692e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  3.743818242393135165e+01,  1.492434857349033628e+01,  0.000000000000000000e+00,
  0.000000000000000000e+00,  6.724128955614088188e-01,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  2.023706156128473044e+00,  9.538479733914937242e+01,  0.000000000000000000e+00,
  0.000000000000000000e+00,  5.004826265911996863e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  1.127780548344367917e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  6.094069061757222627e+00,  3.151299169326539751e+00,  0.000000000000000000e+00, -2.229793403912785976e+01,
  0.000000000000000000e+00,  0.000000000000000000e+00,  5.949596326773392008e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  5.487649125449162391e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  3.861348709205134178e+00,  0.000000000000000000e+00,  6.156604990239477715e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  3.517088703524263726e-01,  0.000000000000000000e+00,  1.303045194835739329e+00,
  1.907212085459561379e+01,  3.604016864926741448e+00,  0.000000000000000000e+00,  1.485223477427147998e+00,
  3.537548507508307072e+00,  1.685092396988776331e+00,  0.000000000000000000e+00,  1.545388085903649067e+00,
  6.610815076327216655e-01,  1.796508602929096865e+00,  2.118675147972728823e+00,  9.987341342119526733e-01,
  0.000000000000000000e+00,  2.088903010142080241e+00,  0.000000000000000000e+00,  7.360098931746055229e-01,
  8.749278618310329936e-01,  1.469515615683545828e+00,  4.036900596565609067e-01,  1.907973950826430398e+00,
  1.129753262912140122e-01,  2.098654055515351669e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
 -4.982390613598663265e+01,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,
  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00,  0.000000000000000000e+00
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

    if (r_idx + s_idx == 0) {
        return ;
    } else if (r_idx == 0) {
        ts_start = pkt_time[0];
        tmp = pkt_time[0];
        ndpi_timer_sub(&tmp, &start_time, &start_m);
    } else if (s_idx == 0) {
        ts_start = pkt_time_twin[0];
        tmp = pkt_time_twin[0];
        ndpi_timer_sub(&tmp, &start_time_twin, &start_m);
    } else {
        if (ndpi_timer_lt(&start_time, &start_time_twin)) {
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
        if (s >= s_idx) {
            merged_lens[s+r] = pkt_len_twin[r];
            tmp = pkt_time_twin[r];
            ndpi_timer_sub(&tmp, &ts_start, &tmp_r);
            merged_times[s+r] = ndpi_timeval_to_milliseconds(tmp_r);
            ts_start = tmp;
            r++;
        } else if (r >= r_idx) {
            merged_lens[s+r] = pkt_len[s];
            tmp = pkt_time[s];
            ndpi_timer_sub(&tmp, &ts_start, &tmp_r);
            merged_times[s+r] = ndpi_timeval_to_milliseconds(tmp_r);
            ts_start = tmp;
            s++;
        } else {
            if (ndpi_timer_lt(&pkt_time[s], &pkt_time_twin[r])) {
                merged_lens[s+r] = pkt_len[s];
	               tmp = pkt_time[s];
	               ndpi_timer_sub(&tmp, &ts_start, &tmp_r);
	               merged_times[s+r] = ndpi_timeval_to_milliseconds(tmp_r);
	               ts_start = tmp;
                s++;
            } else {
                merged_lens[s+r] = pkt_len_twin[r];
	               tmp = pkt_time_twin[r];
	               ndpi_timer_sub(&tmp, &ts_start, &tmp_r);
	               merged_times[s+r] = ndpi_timeval_to_milliseconds(tmp_r);
	               ts_start = tmp;
                r++;
            }
        }
    }
    merged_times[0] = ndpi_timeval_to_milliseconds(start_m);
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

    if (num_packets == 0) {
        // nothing to do
    } else if (num_packets == 1) {
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
            if (row_sum != 0.0) {
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
    if (num_packets == 0) {
        // nothing to do
    } else if (num_packets == 1) {
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
            if (row_sum != 0.0) {
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

    merged_lens = calloc(1, sizeof(uint16_t)*(op_n + ip_n));
    merged_times = calloc(1, sizeof(uint16_t)*(op_n + ip_n));
    if (!merged_lens || !merged_times) {
	free(merged_lens);
	free(merged_times);
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
    if (ob+ib > 100 && use_bd) {
        for (i = 0; i < NUM_BD_VALUES; i++) {
            if (pkt_len_twin != NULL) {
                features[i+8+MC_BINS_LEN*MC_BINS_LEN+MC_BINS_TIME*MC_BINS_TIME] = (bd[i]+bd_t[i])/((float)(ob+ib));
            } else {
                features[i+8+MC_BINS_LEN*MC_BINS_LEN+MC_BINS_TIME*MC_BINS_TIME] = bd[i]/((float)(ob));
            }
        }
    }

    if (ob+ib > 100 && use_bd) {
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

    free(merged_lens);
    free(merged_times);

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
            if (fp != NULL) {
                while (fscanf(fp, "%f", &param) != EOF) {
                    ndpi_parameters_splt[count] = param;
                    count++;
                    if (count >= NUM_PARAMETERS_SPLT_LOGREG) {
	                break;
                    }
                }
                fclose(fp);
            }
            break;

        case (BD_PARAM_TYPE):
            count = 0;
            fp = fopen(param_file,"r");
            if (fp != NULL) {
                while (fscanf(fp, "%f", &param) != EOF) {
                    ndpi_parameters_bd[count] = param;
                    count++;
                    if (count >= NUM_PARAMETERS_BD_LOGREG) {
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
    if (a->tv_sec == b->tv_sec && a->tv_usec == b->tv_usec) {
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
    if (result->tv_usec < 0) {
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
