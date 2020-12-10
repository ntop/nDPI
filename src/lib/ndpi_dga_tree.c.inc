/*
 * ndpi_dga_tree.c.inc
 *
 * Copyright (C) 2011-20 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <math.h>
#include <stdlib.h>
#include <stdio.h>


float dga_predict_proba(float norm_entropy,
                        float gini,
                        float classification_error,
                        int num_non_dga_trigrams,
                        int num_dga_trigrams,
                        int num_trigrams,
                        int total_length,
                        int num_digits,
                        int num_vowels,
                        int num_hexs,
                        int num_consonants,
                        int num_dots) {

  int non_dga, dga;

  if (num_consonants <= 10.5) {
    if (num_dga_trigrams <= 0.5) {
      if (total_length <= 18.5) {
        if (num_non_dga_trigrams <= 0.5) {
          if (total_length <= 9.5) {
            if (num_consonants <= 6.5) {
              if (num_trigrams <= 6.5) {
                if (num_vowels <= 3.5) {
                  if (total_length <= 6.5) {
                    non_dga = 7137;
                    dga = 0;
                  } else {
                    if (num_digits <= 0.5) {
                      non_dga = 32226;
                      dga = 1789;
                    } else {
                      non_dga = 5121;
                      dga = 0;
                    }
                  }
                } else {
                  if (num_consonants <= 2.5) {
                    if (classification_error <= 0.6904765069484711) {
                      non_dga = 234;
                      dga = 2;
                    } else {
                      non_dga = 644;
                      dga = 23;
                    }
                  } else {
                    if (num_hexs <= 0.5) {
                      non_dga = 84;
                      dga = 0;
                    } else {
                      non_dga = 1943;
                      dga = 610;
                    }
                  }
                }
              } else {
                if (num_consonants <= 5.5) {
                  if (num_digits <= 0.5) {
                    if (num_dots <= 1.5) {
                      non_dga = 24976;
                      dga = 186;
                    } else {
                      non_dga = 1489;
                      dga = 0;
                    }
                  } else {
                    non_dga = 4419;
                    dga = 0;
                  }
                } else {
                  if (num_vowels <= 1.5) {
                    non_dga = 695;
                    dga = 0;
                  } else {
                    if (num_hexs <= 2.5) {
                      non_dga = 6313;
                      dga = 185;
                    } else {
                      non_dga = 3218;
                      dga = 156;
                    }
                  }
                }
              }
            } else {
              if (num_vowels <= 0.5) {
                if (classification_error <= 0.7638890147209167) {
                  if (gini <= 0.8136574923992157) {
                    if (gini <= 0.7297455072402954) {
                      non_dga = 13;
                      dga = 0;
                    } else {
                      non_dga = 102;
                      dga = 41;
                    }
                  } else {
                    if (num_consonants <= 7.5) {
                      non_dga = 96;
                      dga = 77;
                    } else {
                      non_dga = 5;
                      dga = 13;
                    }
                  }
                } else {
                  if (num_digits <= 0.5) {
                    if (num_consonants <= 7.5) {
                      non_dga = 44;
                      dga = 54;
                    } else {
                      non_dga = 72;
                      dga = 185;
                    }
                  } else {
                    non_dga = 7;
                    dga = 0;
                  }
                }
              } else {
                if (norm_entropy <= 0.8948450088500977) {
                  if (num_hexs <= 5.5) {
                    if (num_hexs <= 1.5) {
                      non_dga = 272;
                      dga = 21;
                    } else {
                      non_dga = 523;
                      dga = 74;
                    }
                  } else {
                    non_dga = 1;
                    dga = 3;
                  }
                } else {
                  if (num_hexs <= 2.5) {
                    if (norm_entropy <= 0.9649485051631927) {
                      non_dga = 782;
                      dga = 119;
                    } else {
                      non_dga = 484;
                      dga = 90;
                    }
                  } else {
                    if (num_hexs <= 4.5) {
                      non_dga = 421;
                      dga = 102;
                    } else {
                      non_dga = 9;
                      dga = 8;
                    }
                  }
                }
              }
            }
          } else {
            if (num_vowels <= 2.5) {
              if (num_consonants <= 7.5) {
                if (num_consonants <= 6.5) {
                  if (num_hexs <= 9.5) {
                    if (num_digits <= 0.5) {
                      non_dga = 1820;
                      dga = 49;
                    } else {
                      non_dga = 4607;
                      dga = 2;
                    }
                  } else {
                    if (num_digits <= 9.5) {
                      non_dga = 17;
                      dga = 128;
                    } else {
                      non_dga = 35;
                      dga = 4;
                    }
                  }
                } else {
                  if (num_vowels <= 1.5) {
                    if (num_hexs <= 7.5) {
                      non_dga = 1231;
                      dga = 15;
                    } else {
                      non_dga = 0;
                      dga = 4;
                    }
                  } else {
                    if (total_length <= 10.5) {
                      non_dga = 7435;
                      dga = 3116;
                    } else {
                      non_dga = 2228;
                      dga = 206;
                    }
                  }
                }
              } else {
                if (num_dots <= 1.5) {
                  if (num_vowels <= 1.5) {
                    if (num_consonants <= 8.5) {
                      non_dga = 1313;
                      dga = 1753;
                    } else {
                      non_dga = 461;
                      dga = 3448;
                    }
                  } else {
                    if (num_digits <= 0.5) {
                      non_dga = 7207;
                      dga = 9997;
                    } else {
                      non_dga = 440;
                      dga = 189;
                    }
                  }
                } else {
                  if (num_consonants <= 9.5) {
                    if (num_hexs <= 0.5) {
                      non_dga = 74;
                      dga = 0;
                    } else {
                      non_dga = 1601;
                      dga = 465;
                    }
                  } else {
                    if (total_length <= 14.5) {
                      non_dga = 156;
                      dga = 175;
                    } else {
                      non_dga = 22;
                      dga = 0;
                    }
                  }
                }
              }
            } else {
              if (num_consonants <= 9.5) {
                if (num_dots <= 1.5) {
                  if (num_hexs <= 3.5) {
                    if (num_vowels <= 4.5) {
                      non_dga = 125063;
                      dga = 26911;
                    } else {
                      non_dga = 65839;
                      dga = 19683;
                    }
                  } else {
                    if (num_trigrams <= 12.5) {
                      non_dga = 157557;
                      dga = 19524;
                    } else {
                      non_dga = 85974;
                      dga = 15607;
                    }
                  }
                } else {
                  if (classification_error <= 0.7669685184955597) {
                    if (num_trigrams <= 12.5) {
                      non_dga = 2005;
                      dga = 49;
                    } else {
                      non_dga = 1169;
                      dga = 396;
                    }
                  } else {
                    if (num_vowels <= 3.5) {
                      non_dga = 8582;
                      dga = 582;
                    } else {
                      non_dga = 31329;
                      dga = 833;
                    }
                  }
                }
              } else {
                if (num_trigrams <= 13.5) {
                  if (num_dots <= 1.5) {
                    if (norm_entropy <= 0.8683815002441406) {
                      non_dga = 6708;
                      dga = 8389;
                    } else {
                      non_dga = 8606;
                      dga = 6967;
                    }
                  } else {
                    if (gini <= 0.9022224843502045) {
                      non_dga = 427;
                      dga = 71;
                    } else {
                      non_dga = 184;
                      dga = 70;
                    }
                  }
                } else {
                  if (num_dots <= 1.5) {
                    if (num_hexs <= 3.5) {
                      non_dga = 8747;
                      dga = 3214;
                    } else {
                      non_dga = 40025;
                      dga = 7015;
                    }
                  } else {
                    if (num_vowels <= 4.5) {
                      non_dga = 1392;
                      dga = 101;
                    } else {
                      non_dga = 3570;
                      dga = 1991;
                    }
                  }
                }
              }
            }
          }
        } else {
          non_dga = 64422;
          dga = 0;
        }
      } else {
        if (num_dots <= 1.5) {
          if (num_non_dga_trigrams <= 0.5) {
            if (total_length <= 19.5) {
              if (num_vowels <= 7.5) {
                if (num_digits <= 0.5) {
                  if (gini <= 0.9113569855690002) {
                    if (classification_error <= 0.8684209883213043) {
                      non_dga = 747;
                      dga = 97;
                    } else {
                      non_dga = 16;
                      dga = 0;
                    }
                  } else {
                    if (num_hexs <= 2.5) {
                      non_dga = 9;
                      dga = 0;
                    } else {
                      non_dga = 363;
                      dga = 63;
                    }
                  }
                } else {
                  if (num_digits <= 4.5) {
                    if (num_digits <= 1.5) {
                      non_dga = 115;
                      dga = 0;
                    } else {
                      non_dga = 379;
                      dga = 17;
                    }
                  } else {
                    if (num_hexs <= 15.0) {
                      non_dga = 5;
                      dga = 12;
                    } else {
                      non_dga = 12;
                      dga = 0;
                    }
                  }
                }
              } else {
                if (norm_entropy <= 0.8202250003814697) {
                  if (num_vowels <= 9.5) {
                    if (num_vowels <= 8.5) {
                      non_dga = 3031;
                      dga = 4946;
                    } else {
                      non_dga = 873;
                      dga = 2528;
                    }
                  } else {
                    if (num_vowels <= 10.5) {
                      non_dga = 123;
                      dga = 1014;
                    } else {
                      non_dga = 15;
                      dga = 374;
                    }
                  }
                } else {
                  if (norm_entropy <= 0.8567759990692139) {
                    if (num_vowels <= 8.5) {
                      non_dga = 1741;
                      dga = 4990;
                    } else {
                      non_dga = 368;
                      dga = 2206;
                    }
                  } else {
                    if (num_hexs <= 3.5) {
                      non_dga = 31;
                      dga = 612;
                    } else {
                      non_dga = 1076;
                      dga = 6059;
                    }
                  }
                }
              }
            } else {
              if (num_digits <= 4.5) {
                if (num_hexs <= 4.5) {
                  if (num_vowels <= 8.5) {
                    if (num_digits <= 1.5) {
                      non_dga = 149;
                      dga = 20;
                    } else {
                      non_dga = 2;
                      dga = 5;
                    }
                  } else {
                    if (total_length <= 20.5) {
                      non_dga = 364;
                      dga = 1061;
                    } else {
                      non_dga = 143;
                      dga = 24;
                    }
                  }
                } else {
                  if (num_consonants <= 8.5) {
                    if (num_vowels <= 10.5) {
                      non_dga = 56;
                      dga = 19;
                    } else {
                      non_dga = 34;
                      dga = 225;
                    }
                  } else {
                    if (gini <= 0.8751415014266968) {
                      non_dga = 322;
                      dga = 363;
                    } else {
                      non_dga = 3613;
                      dga = 1609;
                    }
                  }
                }
              } else {
                if (num_hexs <= 16.5) {
                  if (total_length <= 22.5) {
                    if (total_length <= 20.5) {
                      non_dga = 3;
                      dga = 6;
                    } else {
                      non_dga = 4;
                      dga = 779;
                    }
                  } else {
                    non_dga = 4;
                    dga = 0;
                  }
                } else {
                  if (total_length <= 26.0) {
                    if (num_hexs <= 17.5) {
                      non_dga = 7;
                      dga = 51;
                    } else {
                      non_dga = 18;
                      dga = 0;
                    }
                  } else {
                    if (num_trigrams <= 36.0) {
                      non_dga = 1;
                      dga = 149;
                    } else {
                      non_dga = 2;
                      dga = 0;
                    }
                  }
                }
              }
            }
          } else {
            non_dga = 2463;
            dga = 0;
          }
        } else {
          if (num_non_dga_trigrams <= 0.5) {
            if (gini <= 0.8805254995822906) {
              if (num_hexs <= 11.5) {
                if (num_hexs <= 3.5) {
                  if (num_trigrams <= 18.5) {
                    if (gini <= 0.8646329939365387) {
                      non_dga = 7;
                      dga = 15;
                    } else {
                      non_dga = 19;
                      dga = 9;
                    }
                  } else {
                    non_dga = 6;
                    dga = 0;
                  }
                } else {
                  if (norm_entropy <= 0.6830574870109558) {
                    if (classification_error <= 0.7184209823608398) {
                      non_dga = 1;
                      dga = 5;
                    } else {
                      non_dga = 4;
                      dga = 1;
                    }
                  } else {
                    if (num_hexs <= 6.5) {
                      non_dga = 105;
                      dga = 17;
                    } else {
                      non_dga = 123;
                      dga = 4;
                    }
                  }
                }
              } else {
                if (num_consonants <= 7.5) {
                  non_dga = 2;
                  dga = 0;
                } else {
                  non_dga = 0;
                  dga = 10;
                }
              }
            } else {
              if (num_hexs <= 11.5) {
                if (classification_error <= 0.8047620058059692) {
                  if (num_hexs <= 4.5) {
                    if (norm_entropy <= 0.8229770064353943) {
                      non_dga = 119;
                      dga = 17;
                    } else {
                      non_dga = 29;
                      dga = 9;
                    }
                  } else {
                    if (gini <= 0.8921085000038147) {
                      non_dga = 287;
                      dga = 11;
                    } else {
                      non_dga = 197;
                      dga = 0;
                    }
                  }
                } else {
                  if (gini <= 0.9200695157051086) {
                    if (num_vowels <= 6.5) {
                      non_dga = 197;
                      dga = 0;
                    } else {
                      non_dga = 2568;
                      dga = 41;
                    }
                  } else {
                    non_dga = 328;
                    dga = 0;
                  }
                }
              } else {
                if (total_length <= 34.0) {
                  if (classification_error <= 0.8708334863185883) {
                    non_dga = 6;
                    dga = 0;
                  } else {
                    if (classification_error <= 0.8819445073604584) {
                      non_dga = 1;
                      dga = 6;
                    } else {
                      non_dga = 4;
                      dga = 0;
                    }
                  }
                } else {
                  non_dga = 0;
                  dga = 9;
                }
              }
            }
          } else {
            non_dga = 3631;
            dga = 0;
          }
        }
      }
    } else {
      non_dga = 0;
      dga = 29989;
    }
  } else {
    if (num_dots <= 1.5) {
      if (num_dga_trigrams <= 0.5) {
        if (num_consonants <= 12.5) {
          if (total_length <= 19.5) {
            if (total_length <= 18.5) {
              if (num_vowels <= 3.5) {
                if (num_non_dga_trigrams <= 0.5) {
                  if (num_consonants <= 11.5) {
                    if (num_trigrams <= 13.5) {
                      non_dga = 1726;
                      dga = 13872;
                    } else {
                      non_dga = 145;
                      dga = 166;
                    }
                  } else {
                    if (total_length <= 15.5) {
                      non_dga = 54;
                      dga = 6647;
                    } else {
                      non_dga = 500;
                      dga = 9566;
                    }
                  }
                } else {
                  non_dga = 218;
                  dga = 0;
                }
              } else {
                if (num_consonants <= 11.5) {
                  if (num_trigrams <= 14.5) {
                    if (num_hexs <= 2.5) {
                      non_dga = 739;
                      dga = 1800;
                    } else {
                      non_dga = 4839;
                      dga = 5305;
                    }
                  } else {
                    if (classification_error <= 0.8856210112571716) {
                      non_dga = 21211;
                      dga = 5613;
                    } else {
                      non_dga = 3883;
                      dga = 2837;
                    }
                  }
                } else {
                  if (gini <= 0.9166665077209473) {
                    if (norm_entropy <= 0.8459400236606598) {
                      non_dga = 3661;
                      dga = 2632;
                    } else {
                      non_dga = 3151;
                      dga = 3732;
                    }
                  } else {
                    if (num_vowels <= 4.5) {
                      non_dga = 518;
                      dga = 598;
                    } else {
                      non_dga = 1243;
                      dga = 3880;
                    }
                  }
                }
              }
            } else {
              if (norm_entropy <= 0.8567759990692139) {
                if (num_consonants <= 11.5) {
                  if (num_vowels <= 6.5) {
                    if (num_non_dga_trigrams <= 0.5) {
                      non_dga = 684;
                      dga = 108;
                    } else {
                      non_dga = 213;
                      dga = 0;
                    }
                  } else {
                    if (norm_entropy <= 0.7978630065917969) {
                      non_dga = 2043;
                      dga = 3208;
                    } else {
                      non_dga = 5225;
                      dga = 14779;
                    }
                  }
                } else {
                  if (num_vowels <= 5.5) {
                    if (num_non_dga_trigrams <= 0.5) {
                      non_dga = 235;
                      dga = 61;
                    } else {
                      non_dga = 85;
                      dga = 0;
                    }
                  } else {
                    if (norm_entropy <= 0.8072159886360168) {
                      non_dga = 1607;
                      dga = 4193;
                    } else {
                      non_dga = 3597;
                      dga = 18979;
                    }
                  }
                }
              } else {
                if (num_vowels <= 5.5) {
                  if (num_non_dga_trigrams <= 0.5) {
                    if (num_vowels <= 3.5) {
                      non_dga = 4;
                      dga = 24;
                    } else {
                      non_dga = 365;
                      dga = 83;
                    }
                  } else {
                    non_dga = 147;
                    dga = 0;
                  }
                } else {
                  if (num_consonants <= 11.5) {
                    if (num_vowels <= 6.5) {
                      non_dga = 677;
                      dga = 73;
                    } else {
                      non_dga = 2707;
                      dga = 16397;
                    }
                  } else {
                    if (norm_entropy <= 0.8791375160217285) {
                      non_dga = 1708;
                      dga = 15284;
                    } else {
                      non_dga = 1130;
                      dga = 17289;
                    }
                  }
                }
              }
            }
          } else {
            if (num_non_dga_trigrams <= 0.5) {
              if (num_digits <= 2.5) {
                if (classification_error <= 0.803846001625061) {
                  if (num_vowels <= 7.5) {
                    if (num_consonants <= 11.5) {
                      non_dga = 295;
                      dga = 52;
                    } else {
                      non_dga = 2352;
                      dga = 4620;
                    }
                  } else {
                    if (num_hexs <= 6.5) {
                      non_dga = 1871;
                      dga = 1839;
                    } else {
                      non_dga = 2517;
                      dga = 1332;
                    }
                  }
                } else {
                  if (gini <= 0.9215439856052399) {
                    if (total_length <= 22.5) {
                      non_dga = 21270;
                      dga = 8493;
                    } else {
                      non_dga = 2041;
                      dga = 1778;
                    }
                  } else {
                    if (num_trigrams <= 18.5) {
                      non_dga = 1150;
                      dga = 663;
                    } else {
                      non_dga = 982;
                      dga = 2333;
                    }
                  }
                }
              } else {
                if (num_vowels <= 6.5) {
                  if (num_digits <= 4.5) {
                    if (num_trigrams <= 18.5) {
                      non_dga = 30;
                      dga = 12;
                    } else {
                      non_dga = 98;
                      dga = 1184;
                    }
                  } else {
                    if (total_length <= 22.5) {
                      non_dga = 1;
                      dga = 1127;
                    } else {
                      non_dga = 4;
                      dga = 74;
                    }
                  }
                } else {
                  if (num_trigrams <= 20.5) {
                    if (gini <= 0.9152890145778656) {
                      non_dga = 11;
                      dga = 13;
                    } else {
                      non_dga = 11;
                      dga = 82;
                    }
                  } else {
                    if (num_digits <= 5.5) {
                      non_dga = 94;
                      dga = 0;
                    } else {
                      non_dga = 0;
                      dga = 26;
                    }
                  }
                }
              }
            } else {
              non_dga = 2639;
              dga = 0;
            }
          }
        } else {
          if (num_vowels <= 5.5) {
            if (num_non_dga_trigrams <= 0.5) {
              if (num_vowels <= 4.5) {
                if (num_consonants <= 13.5) {
                  if (num_vowels <= 2.5) {
                    if (norm_entropy <= 0.6487410068511963) {
                      non_dga = 1;
                      dga = 1;
                    } else {
                      non_dga = 27;
                      dga = 10935;
                    }
                  } else {
                    if (gini <= 0.9201900064945221) {
                      non_dga = 971;
                      dga = 6716;
                    } else {
                      non_dga = 112;
                      dga = 4994;
                    }
                  }
                } else {
                  if (num_vowels <= 3.5) {
                    if (num_consonants <= 14.5) {
                      non_dga = 61;
                      dga = 16206;
                    } else {
                      non_dga = 24;
                      dga = 43332;
                    }
                  } else {
                    if (norm_entropy <= 0.8658744990825653) {
                      non_dga = 278;
                      dga = 20824;
                    } else {
                      non_dga = 141;
                      dga = 38414;
                    }
                  }
                }
              } else {
                if (norm_entropy <= 0.8655014932155609) {
                  if (num_trigrams <= 17.5) {
                    if (norm_entropy <= 0.8202250003814697) {
                      non_dga = 853;
                      dga = 6758;
                    } else {
                      non_dga = 842;
                      dga = 14397;
                    }
                  } else {
                    if (num_hexs <= 9.5) {
                      non_dga = 1597;
                      dga = 5284;
                    } else {
                      non_dga = 11;
                      dga = 1192;
                    }
                  }
                } else {
                  if (total_length <= 19.5) {
                    if (norm_entropy <= 0.886850506067276) {
                      non_dga = 583;
                      dga = 16387;
                    } else {
                      non_dga = 447;
                      dga = 25193;
                    }
                  } else {
                    if (num_hexs <= 4.5) {
                      non_dga = 165;
                      dga = 1007;
                    } else {
                      non_dga = 326;
                      dga = 5733;
                    }
                  }
                }
              }
            } else {
              non_dga = 1276;
              dga = 0;
            }
          } else {
            if (gini <= 0.9183775186538696) {
              if (num_trigrams <= 22.5) {
                if (total_length <= 21.5) {
                  if (classification_error <= 0.8047620058059692) {
                    if (num_trigrams <= 18.5) {
                      non_dga = 961;
                      dga = 5781;
                    } else {
                      non_dga = 352;
                      dga = 206;
                    }
                  } else {
                    if (num_hexs <= 5.5) {
                      non_dga = 3682;
                      dga = 2369;
                    } else {
                      non_dga = 4514;
                      dga = 8670;
                    }
                  }
                } else {
                  if (norm_entropy <= 0.8216594755649567) {
                    if (total_length <= 22.5) {
                      non_dga = 5627;
                      dga = 1187;
                    } else {
                      non_dga = 10761;
                      dga = 7288;
                    }
                  } else {
                    if (num_trigrams <= 20.5) {
                      non_dga = 1757;
                      dga = 1508;
                    } else {
                      non_dga = 849;
                      dga = 3377;
                    }
                  }
                }
              } else {
                if (norm_entropy <= 0.7792600095272064) {
                  if (num_non_dga_trigrams <= 0.5) {
                    if (num_trigrams <= 24.5) {
                      non_dga = 3540;
                      dga = 2987;
                    } else {
                      non_dga = 5062;
                      dga = 8753;
                    }
                  } else {
                    non_dga = 589;
                    dga = 0;
                  }
                } else {
                  if (num_hexs <= 8.5) {
                    if (num_trigrams <= 23.5) {
                      non_dga = 1309;
                      dga = 13093;
                    } else {
                      non_dga = 1380;
                      dga = 3843;
                    }
                  } else {
                    if (num_trigrams <= 23.5) {
                      non_dga = 549;
                      dga = 241;
                    } else {
                      non_dga = 826;
                      dga = 1970;
                    }
                  }
                }
              }
            } else {
              if (num_non_dga_trigrams <= 0.5) {
                if (gini <= 0.9260275065898895) {
                  if (num_consonants <= 14.5) {
                    if (classification_error <= 0.8480769991874695) {
                      non_dga = 480;
                      dga = 3600;
                    } else {
                      non_dga = 5862;
                      dga = 12617;
                    }
                  } else {
                    if (classification_error <= 0.8481554985046387) {
                      non_dga = 818;
                      dga = 17090;
                    } else {
                      non_dga = 4100;
                      dga = 28131;
                    }
                  }
                } else {
                  if (gini <= 0.9316419959068298) {
                    if (classification_error <= 0.8675439953804016) {
                      non_dga = 498;
                      dga = 18881;
                    } else {
                      non_dga = 3042;
                      dga = 27717;
                    }
                  } else {
                    if (num_trigrams <= 22.5) {
                      non_dga = 512;
                      dga = 9928;
                    } else {
                      non_dga = 488;
                      dga = 26533;
                    }
                  }
                }
              } else {
                non_dga = 1495;
                dga = 0;
              }
            }
          }
        }
      } else {
        non_dga = 0;
        dga = 175782;
      }
    } else {
      if (num_dga_trigrams <= 0.5) {
        if (num_non_dga_trigrams <= 0.5) {
          if (total_length <= 24.5) {
            if (num_vowels <= 3.5) {
              if (num_consonants <= 12.5) {
                if (num_vowels <= 2.5) {
                  if (num_digits <= 0.5) {
                    if (norm_entropy <= 0.8860859870910645) {
                      non_dga = 78;
                      dga = 132;
                    } else {
                      non_dga = 14;
                      dga = 138;
                    }
                  } else {
                    if (total_length <= 18.0) {
                      non_dga = 19;
                      dga = 0;
                    } else {
                      non_dga = 1;
                      dga = 1;
                    }
                  }
                } else {
                  if (num_hexs <= 12.0) {
                    if (num_digits <= 0.5) {
                      non_dga = 396;
                      dga = 130;
                    } else {
                      non_dga = 68;
                      dga = 1;
                    }
                  } else {
                    non_dga = 0;
                    dga = 5;
                  }
                }
              } else {
                if (num_vowels <= 2.5) {
                  if (num_consonants <= 13.5) {
                    if (num_trigrams <= 15.5) {
                      non_dga = 9;
                      dga = 90;
                    } else {
                      non_dga = 3;
                      dga = 2;
                    }
                  } else {
                    if (norm_entropy <= 0.8405010104179382) {
                      non_dga = 8;
                      dga = 380;
                    } else {
                      non_dga = 1;
                      dga = 543;
                    }
                  }
                } else {
                  if (gini <= 0.9197105169296265) {
                    if (num_digits <= 0.5) {
                      non_dga = 81;
                      dga = 777;
                    } else {
                      non_dga = 13;
                      dga = 17;
                    }
                  } else {
                    if (norm_entropy <= 0.9082860052585602) {
                      non_dga = 20;
                      dga = 431;
                    } else {
                      non_dga = 0;
                      dga = 159;
                    }
                  }
                }
              }
            } else {
              if (num_hexs <= 7.5) {
                if (num_trigrams <= 18.5) {
                  if (total_length <= 17.5) {
                    if (classification_error <= 0.7941175103187561) {
                      non_dga = 33;
                      dga = 20;
                    } else {
                      non_dga = 634;
                      dga = 14;
                    }
                  } else {
                    if (total_length <= 18.5) {
                      non_dga = 1553;
                      dga = 1789;
                    } else {
                      non_dga = 5334;
                      dga = 2517;
                    }
                  }
                } else {
                  if (num_consonants <= 11.5) {
                    if (total_length <= 21.5) {
                      non_dga = 775;
                      dga = 14;
                    } else {
                      non_dga = 535;
                      dga = 1;
                    }
                  } else {
                    if (num_vowels <= 6.5) {
                      non_dga = 3546;
                      dga = 586;
                    } else {
                      non_dga = 5544;
                      dga = 2518;
                    }
                  }
                }
              } else {
                if (num_hexs <= 11.5) {
                  if (num_vowels <= 9.5) {
                    if (num_digits <= 0.5) {
                      non_dga = 2167;
                      dga = 2442;
                    } else {
                      non_dga = 359;
                      dga = 158;
                    }
                  } else {
                    if (norm_entropy <= 0.786177009344101) {
                      non_dga = 87;
                      dga = 0;
                    } else {
                      non_dga = 84;
                      dga = 1;
                    }
                  }
                } else {
                  if (num_consonants <= 13.5) {
                    if (num_hexs <= 12.5) {
                      non_dga = 24;
                      dga = 75;
                    } else {
                      non_dga = 3;
                      dga = 92;
                    }
                  } else {
                    non_dga = 0;
                    dga = 191;
                  }
                }
              }
            }
          } else {
            if (num_digits <= 0.5) {
              if (num_vowels <= 4.5) {
                if (gini <= 0.9236485064029694) {
                  non_dga = 4;
                  dga = 0;
                } else {
                  non_dga = 1;
                  dga = 6;
                }
              } else {
                if (classification_error <= 0.8393549919128418) {
                  if (num_trigrams <= 23.5) {
                    non_dga = 253;
                    dga = 0;
                  } else {
                    if (num_consonants <= 20.5) {
                      non_dga = 1612;
                      dga = 32;
                    } else {
                      non_dga = 144;
                      dga = 0;
                    }
                  }
                } else {
                  if (num_hexs <= 8.5) {
                    if (num_vowels <= 5.5) {
                      non_dga = 90;
                      dga = 3;
                    } else {
                      non_dga = 8582;
                      dga = 25;
                    }
                  } else {
                    if (num_trigrams <= 31.5) {
                      non_dga = 2039;
                      dga = 24;
                    } else {
                      non_dga = 822;
                      dga = 2;
                    }
                  }
                }
              }
            } else {
              if (num_vowels <= 6.5) {
                if (total_length <= 27.5) {
                  if (num_digits <= 1.5) {
                    if (num_consonants <= 15.5) {
                      non_dga = 1;
                      dga = 1;
                    } else {
                      non_dga = 30;
                      dga = 1;
                    }
                  } else {
                    non_dga = 115;
                    dga = 0;
                  }
                } else {
                  if (num_vowels <= 5.5) {
                    if (num_consonants <= 15.5) {
                      non_dga = 7;
                      dga = 25;
                    } else {
                      non_dga = 2;
                      dga = 258;
                    }
                  } else {
                    if (num_hexs <= 8.5) {
                      non_dga = 11;
                      dga = 4;
                    } else {
                      non_dga = 22;
                      dga = 92;
                    }
                  }
                }
              } else {
                if (total_length <= 27.5) {
                  if (classification_error <= 0.7735045254230499) {
                    non_dga = 1;
                    dga = 1;
                  } else {
                    non_dga = 327;
                    dga = 0;
                  }
                } else {
                  if (num_vowels <= 7.5) {
                    if (num_hexs <= 9.5) {
                      non_dga = 38;
                      dga = 6;
                    } else {
                      non_dga = 32;
                      dga = 40;
                    }
                  } else {
                    if (num_consonants <= 11.5) {
                      non_dga = 0;
                      dga = 3;
                    } else {
                      non_dga = 347;
                      dga = 25;
                    }
                  }
                }
              }
            }
          }
        } else {
          non_dga = 28693;
          dga = 0;
        }
      } else {
        non_dga = 0;
        dga = 8795;
      }
    }
  }
  return (float)dga/(dga+non_dga);
}
