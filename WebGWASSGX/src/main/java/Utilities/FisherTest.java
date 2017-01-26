/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utilities;

/**
 *
 * @author azizmma
 */
public class FisherTest {

    double SMALLISH_EPSILON = 0.00000000003;
    double SMALL_EPSILON = 0.0000000000001;
    double EXACT_TEST_BIAS = 0.00000000000000000000000010339757656912845935892608650874535669572651386260986328125;
    int dir = 0;

    public double fisher23(int m11, int m12, int m13, int m21, int m22, int m23, int midp) {
        // 2x3 Fisher-Freeman-Halton exact test p-value calculation.
        // The number of tables involved here is still small enough that the network
        // algorithm (and the improved variants thereof that I've seen) are
        // suboptimal; a 2-dimensional version of the SNPHWE2 strategy has higher
        // performance.
        // 2x4, 2x5, and 3x3 should also be practical with this method, but beyond
        // that I doubt it's worth the trouble.
        // Complexity of approach is O(n^{df/2}), where n is number of observations.
        double cur_prob = (1 - SMALLISH_EPSILON) * EXACT_TEST_BIAS;
        double tprob = cur_prob;
        double cprob = 0;
        double dyy = 0;
        int tie_ct = 1;
        int dir = 0; // 0 = forwards, 1 = backwards
        double base_probl;
        double base_probr;
        double orig_base_probl;
        double orig_base_probr;
        double orig_row_prob;
        double row_prob;
        int uii;
        int ujj;
        int ukk;
        double cur11;
        double cur21;
        double savedl12;
        double savedl13;
        double savedl22;
        double savedl23;
        double savedr12;
        double savedr13;
        double savedr22;
        double savedr23;
        double orig_savedl12;
        double orig_savedl13;
        double orig_savedl22;
        double orig_savedl23;
        double orig_savedr12;
        double orig_savedr13;
        double orig_savedr22;
        double orig_savedr23;
        double tmp12;
        double tmp13;
        double tmp22;
        double tmp23;
        double dxx = 0.0;
        double preaddp;
        // Ensure m11 + m21 <= m12 + m22 <= m13 + m23.
        uii = m11 + m21;
        ujj = m12 + m22;
        if (uii > ujj) {
            ukk = m11;
            m11 = m12;
            m12 = ukk;
            ukk = m21;
            m21 = m22;
            m22 = ukk;
            ukk = uii;
            uii = ujj;
            ujj = ukk;
        }
        ukk = m13 + m23;
        if (ujj > ukk) {
            ujj = ukk;
            ukk = m12;
            m12 = m13;
            m13 = ukk;
            ukk = m22;
            m22 = m23;
            m23 = ukk;
        }
        if (uii > ujj) {
            ukk = m11;
            m11 = m12;
            m12 = ukk;
            ukk = m21;
            m21 = m22;
            m22 = ukk;
        }
        // Ensure majority of probability mass is in front of m11.
        if ((((int) m11) * (m22 + m23)) > (((int) m21) * (m12 + m13))) {
            ukk = m11;
            m11 = m21;
            m21 = ukk;
            ukk = m12;
            m12 = m22;
            m22 = ukk;
            ukk = m13;
            m13 = m23;
            m23 = ukk;
        }
        if ((((int) m12) * m23) > (((int) m13) * m22)) {
            base_probr = cur_prob;
            savedr12 = m12;
            savedr13 = m13;
            savedr22 = m22;
            savedr23 = m23;
            tmp12 = savedr12;
            tmp13 = savedr13;
            tmp22 = savedr22;
            tmp23 = savedr23;
            // m12 and m23 must be nonzero
            dxx = tmp12 * tmp23;
            do {
                tmp13 += 1;
                tmp22 += 1;
                cur_prob *= dxx / (tmp13 * tmp22);
                tmp12 -= 1;
                tmp23 -= 1;
                if (cur_prob <= EXACT_TEST_BIAS) {
                    if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
                        tie_ct++;
                    }
                    tprob += cur_prob;
                    break;
                }
                cprob += cur_prob;
                if (cprob == Double.MAX_VALUE) {
                    return 0;
                }
                dxx = tmp12 * tmp23;
                // must enforce tmp12 >= 0 and tmp23 >= 0 since we're saving these
            } while (dxx > 0.5);
            savedl12 = tmp12;
            savedl13 = tmp13;
            savedl22 = tmp22;
            savedl23 = tmp23;
            base_probl = cur_prob;
            do {
                tmp13 += 1;
                tmp22 += 1;
                cur_prob *= (tmp12 * tmp23) / (tmp13 * tmp22);
                tmp12 -= 1;
                tmp23 -= 1;
                preaddp = tprob;
                tprob += cur_prob;
            } while (tprob > preaddp);
            tmp12 = savedr12;
            tmp13 = savedr13;
            tmp22 = savedr22;
            tmp23 = savedr23;
            cur_prob = base_probr;
            do {
                tmp12 += 1;
                tmp23 += 1;
                cur_prob *= (tmp13 * tmp22) / (tmp12 * tmp23);
                tmp13 -= 1;
                tmp22 -= 1;
                preaddp = tprob;
                tprob += cur_prob;
            } while (tprob > preaddp);
        } else {
            base_probl = cur_prob;
            savedl12 = m12;
            savedl13 = m13;
            savedl22 = m22;
            savedl23 = m23;
            if (((((int) m12) * m23) + (((int) m13) * m22)) != 0) {
                base_probr = cur_prob;
                savedr12 = savedl12;
                savedr13 = savedl13;
                savedr22 = savedl22;
                savedr23 = savedl23;
            } else {
                tmp12 = savedl12;
                tmp13 = savedl13;
                tmp22 = savedl22;
                tmp23 = savedl23;
                dxx = tmp13 * tmp22;
                do {
                    tmp12 += 1;
                    tmp23 += 1;
                    cur_prob *= dxx / (tmp12 * tmp23);
                    tmp13 -= 1;
                    tmp22 -= 1;
                    if (cur_prob <= EXACT_TEST_BIAS) {
                        if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
                            tie_ct++;
                        }
                        tprob += cur_prob;
                        break;
                    }
                    cprob += cur_prob;
                    if (cprob == Double.MAX_VALUE) {
                        return 0;
                    }
                    dxx = tmp13 * tmp22;
                } while (dxx > 0.5);
                savedr12 = tmp12;
                savedr13 = tmp13;
                savedr22 = tmp22;
                savedr23 = tmp23;
                base_probr = cur_prob;
                do {
                    tmp12 += 1;
                    tmp23 += 1;
                    cur_prob *= (tmp13 * tmp22) / (tmp12 * tmp23);
                    tmp13 -= 1;
                    tmp22 -= 1;
                    preaddp = tprob;
                    tprob += cur_prob;
                } while (tprob > preaddp);
                tmp12 = savedl12;
                tmp13 = savedl13;
                tmp22 = savedl22;
                tmp23 = savedl23;
                cur_prob = base_probl;
                do {
                    tmp13 += 1;
                    tmp22 += 1;
                    cur_prob *= (tmp12 * tmp23) / (tmp13 * tmp22);
                    tmp12 -= 1;
                    tmp23 -= 1;
                    preaddp = tprob;
                    tprob += cur_prob;
                } while (tprob > preaddp);
            }
        }
        row_prob = tprob + cprob;
        orig_base_probl = base_probl;
        orig_base_probr = base_probr;
        orig_row_prob = row_prob;
        orig_savedl12 = savedl12;
        orig_savedl13 = savedl13;
        orig_savedl22 = savedl22;
        orig_savedl23 = savedl23;
        orig_savedr12 = savedr12;
        orig_savedr13 = savedr13;
        orig_savedr22 = savedr22;
        orig_savedr23 = savedr23;
        for (; dir < 2; dir++) {
            cur11 = m11;
            cur21 = m21;
            if (dir != 0) {
                base_probl = orig_base_probl;
                base_probr = orig_base_probr;
                row_prob = orig_row_prob;
                savedl12 = orig_savedl12;
                savedl13 = orig_savedl13;
                savedl22 = orig_savedl22;
                savedl23 = orig_savedl23;
                savedr12 = orig_savedr12;
                savedr13 = orig_savedr13;
                savedr22 = orig_savedr22;
                savedr23 = orig_savedr23;
                ukk = m11;
                if (ukk > m22 + m23) {
                    ukk = m22 + m23;
                }
            } else {
                ukk = m21;
                if (ukk > m12 + m13) {
                    ukk = m12 + m13;
                }
            }
            ukk++;
            while (--ukk > 0) {
                if (dir != 0) {
                    cur21 += 1;
                    if (savedl23 != 0) {
                        savedl13 += 1;
                        row_prob *= (cur11 * (savedl22 + savedl23)) / (cur21 * (savedl12 + savedl13));
                        base_probl *= (cur11 * savedl23) / (cur21 * savedl13);
                        savedl23 -= 1;
                    } else {
                        savedl12 += 1;
                        row_prob *= (cur11 * (savedl22 + savedl23)) / (cur21 * (savedl12 + savedl13));
                        base_probl *= (cur11 * savedl22) / (cur21 * savedl12);
                        savedl22 -= 1;
                    }
                    cur11 -= 1;
                } else {
                    cur11 += 1;
                    if (savedl12 != 0) {
                        savedl22 += 1;
                        row_prob *= (cur21 * (savedl12 + savedl13)) / (cur11 * (savedl22 + savedl23));
                        base_probl *= (cur21 * savedl12) / (cur11 * savedl22);
                        savedl12 -= 1;
                    } else {
                        savedl23 += 1;
                        row_prob *= (cur21 * (savedl12 + savedl13)) / (cur11 * (savedl22 + savedl23));
                        base_probl *= (cur21 * savedl13) / (cur11 * savedl23);
                        savedl13 -= 1;
                    }
                    cur21 -= 1;
                }
                if (fisher23_tailsum(base_probl, savedl12, savedl13, savedl22, savedl23, dxx, tie_ct, 0) != 0) {
                    break;
                }
                tprob += dxx;
                if (dir != 0) {
                    if (savedr22 != 0) {
                        savedr12 += 1;
                        base_probr *= ((cur11 + 1) * savedr22) / (cur21 * savedr12);
                        savedr22 -= 1;
                    } else {
                        savedr13 += 1;
                        base_probr *= ((cur11 + 1) * savedr23) / (cur21 * savedr13);
                        savedr23 -= 1;
                    }
                } else {
                    if (savedr13 != 0) {
                        savedr23 += 1;
                        base_probr *= ((cur21 + 1) * savedr13) / (cur11 * savedr23);
                        savedr13 -= 1;
                    } else {
                        savedr22 += 1;
                        base_probr *= ((cur21 + 1) * savedr12) / (cur11 * savedr22);
                        savedr12 -= 1;
                    }
                }
                fisher23_tailsum(base_probr, savedr12, savedr13, savedr22, savedr23, dyy, tie_ct, 1);
                tprob += dyy;
                cprob += row_prob - dxx - dyy;
                if (cprob == Double.MAX_VALUE) {
                    return 0;
                }
            }
            if (ukk != 0) {
                continue;
            }
            savedl12 += savedl13;
            savedl22 += savedl23;
            if (dir != 0) {
                while (true) {
                    preaddp = tprob;
                    tprob += row_prob;
                    if (tprob <= preaddp) {
                        break;
                    }
                    cur21 += 1;
                    savedl12 += 1;
                    row_prob *= (cur11 * savedl22) / (cur21 * savedl12);
                    cur11 -= 1;
                    savedl22 -= 1;
                }
            } else {
                while (true) {
                    preaddp = tprob;
                    tprob += row_prob;
                    if (tprob <= preaddp) {
                        break;
                    }
                    cur11 += 1;
                    savedl22 += 1;
                    row_prob *= (cur21 * savedl12) / (cur11 * savedl22);
                    cur21 -= 1;
                    savedl12 -= 1;
                }
            }
        }
        if (midp != 0) {
            return tprob / (tprob + cprob);
        } else {
            return (tprob - ((1 - SMALLISH_EPSILON) * EXACT_TEST_BIAS * 0.5) * ((int) tie_ct)) / (tprob + cprob);
        }
    }

    private int fisher23_tailsum(double base_probp, double saved12p, double saved13p, double saved22p, double saved23p, double totalp, int tie_ctp, int right_side) {
        double total = 0;
        double cur_prob = base_probp;
        double tmp12 = saved12p;
        double tmp13 = saved13p;
        double tmp22 = saved22p;
        double tmp23 = saved23p;
        double tmps12;
        double tmps13;
        double tmps22;
        double tmps23;
        double prev_prob;
        // identify beginning of tail
        if (right_side != 0) {
            if (cur_prob > EXACT_TEST_BIAS) {
                prev_prob = tmp13 * tmp22;
                while (prev_prob > 0.5) {
                    tmp12 += 1;
                    tmp23 += 1;
                    cur_prob *= prev_prob / (tmp12 * tmp23);
                    tmp13 -= 1;
                    tmp22 -= 1;
                    if (cur_prob <= EXACT_TEST_BIAS) {
                        break;
                    }
                    prev_prob = tmp13 * tmp22;
                }
                base_probp = cur_prob;
                tmps12 = tmp12;
                tmps13 = tmp13;
                tmps22 = tmp22;
                tmps23 = tmp23;
            } else {
                tmps12 = tmp12;
                tmps13 = tmp13;
                tmps22 = tmp22;
                tmps23 = tmp23;
                while (true) {
                    prev_prob = cur_prob;
                    tmp13 += 1;
                    tmp22 += 1;
                    cur_prob *= (tmp12 * tmp23) / (tmp13 * tmp22);
                    if (cur_prob < prev_prob) {
                        return 1;
                    }
                    tmp12 -= 1;
                    tmp23 -= 1;
                    if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
                        // throw in extra (1 - SMALL_EPSILON) multiplier to prevent rounding
                        // errors from causing this to keep going when the left-side test
                        // stopped
                        if (cur_prob > (1 - SMALL_EPSILON) * EXACT_TEST_BIAS) {
                            break;
                        }
                        tie_ctp += 1;
                    }
                    total += cur_prob;
                }
                prev_prob = cur_prob;
                cur_prob = base_probp;
                base_probp = prev_prob;
            }
        } else {
            if (cur_prob > EXACT_TEST_BIAS) {
                prev_prob = tmp12 * tmp23;
                while (prev_prob > 0.5) {
                    tmp13 += 1;
                    tmp22 += 1;
                    cur_prob *= prev_prob / (tmp13 * tmp22);
                    tmp12 -= 1;
                    tmp23 -= 1;
                    if (cur_prob <= EXACT_TEST_BIAS) {
                        break;
                    }
                    prev_prob = tmp12 * tmp23;
                }
                base_probp = cur_prob;
                tmps12 = tmp12;
                tmps13 = tmp13;
                tmps22 = tmp22;
                tmps23 = tmp23;
            } else {
                tmps12 = tmp12;
                tmps13 = tmp13;
                tmps22 = tmp22;
                tmps23 = tmp23;
                while (true) {
                    prev_prob = cur_prob;
                    tmp12 += 1;
                    tmp23 += 1;
                    cur_prob *= (tmp13 * tmp22) / (tmp12 * tmp23);
                    if (cur_prob < prev_prob) {
                        return 1;
                    }
                    tmp13 -= 1;
                    tmp22 -= 1;
                    if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
                        if (cur_prob > EXACT_TEST_BIAS) {
                            break;
                        }
                        tie_ctp += 1;
                    }
                    total += cur_prob;
                }
                prev_prob = cur_prob;
                cur_prob = base_probp;
                base_probp = prev_prob;
            }
        }
        saved12p = tmp12;
        saved13p = tmp13;
        saved22p = tmp22;
        saved23p = tmp23;
        if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
            if (cur_prob > EXACT_TEST_BIAS) {
                // even most extreme table on this side is too probable
                totalp = 0;
                return 0;
            }
            tie_ctp += 1;
        }
        // sum tail to floating point precision limit
        if (right_side != 0) {
            prev_prob = total;
            total += cur_prob;
            while (total > prev_prob) {
                tmps12 += 1;
                tmps23 += 1;
                cur_prob *= (tmps13 * tmps22) / (tmps12 * tmps23);
                tmps13 -= 1;
                tmps22 -= 1;
                prev_prob = total;
                total += cur_prob;
            }
        } else {
            prev_prob = total;
            total += cur_prob;
            while (total > prev_prob) {
                tmps13 += 1;
                tmps22 += 1;
                cur_prob *= (tmps12 * tmps23) / (tmps13 * tmps22);
                tmps12 -= 1;
                tmps23 -= 1;
                prev_prob = total;
                total += cur_prob;
            }
        }
        totalp = total;
        return 0;
    }
}
