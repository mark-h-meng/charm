'''
John Bethencourt, Brent Waters (Pairing-based)
 
| From: "Ciphertext-Policy Attribute-Based Encryption".
| Published in: 2007
| Available from: 
| Notes: 
| Security Assumption: 
|
| type:           ciphertext-policy attribute-based encryption (public key)
| setting:        Pairing

:Authors:    J Ayo Akinyele
:Date:            04/2011
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output

## START: Add for the el-gamal support
from charm.toolbox.eccurve import prime192v2
from charm.toolbox.ecgroup import ECGroup
from charm.schemes.pkenc.pkenc_elgamal85 import ElGamal
## END

# type annotations
pk_t = { 'g':G1, 'g2':G2, 'h':G1, 'f':G1, 'e_gg_alpha':GT }
mk_t = {'beta':ZR, 'alpha':ZR, 'g2_alpha':G2 }
sk_t = { 'D':G2, 'Dp':G2 ,'Dj':G2, 'Djp':G1, 'S':str }
ct_t = { 'C_tilde':GT, 'C':G1, 'Cpp':G1, 'Cy':G1, 'Cyp':G2 }

debug = False
class CPabe_ASTAR(ABEnc):
    """
    >>> from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
    >>> group = PairingGroup('SS512')
    >>> cpabe = CPabe_BSW07(group)
    >>> msg = group.random(GT)
    >>> attributes = ['ONE', 'TWO', 'THREE']
    >>> access_policy = '((four or three) and (three or one))'
    >>> (master_public_key, master_key) = cpabe.setup()
    >>> secret_key = cpabe.keygen(master_public_key, master_key, attributes)
    >>> cipher_text = cpabe.encrypt(master_public_key, msg, access_policy)
    >>> decrypted_msg = cpabe.decrypt(master_public_key, secret_key, cipher_text)
    >>> msg == decrypted_msg
    True
    """ 
         
    def __init__(self, groupObj, groupObjEc=None):
        ABEnc.__init__(self)
        global util, group       
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj

    @Output(pk_t, mk_t)    
    def setup(self):
        g, gp = group.random(G1), group.random(G2)
        alpha, beta = group.random(ZR), group.random(ZR)
        # initialize pre-processing for generators
        g.initPP(); gp.initPP()
        
        h = g ** beta; f = g ** ~beta
        e_gg_alpha = pair(g, gp ** alpha)
        
        pk = { 'g':g, 'g2':gp, 'h':h, 'f':f, 'e_gg_alpha':e_gg_alpha }
        mk = {'beta':beta, 'alpha':alpha, 'g2_alpha':gp ** alpha }
        return (pk, mk)
    
    @Input(pk_t)
    @Output(tuple)
    def keygen_user(self, pk):
        x_u = group.random(ZR)
        sk_u = x_u
        pk_u = (pk['g2'] ** x_u)
        return (pk_u, sk_u)
        
    @Input(pk_t, mk_t, G2, G2, [str])
    @Output(sk_t)
    def keygen_proxy(self, pk, mk, pk_u, pk_cs, S):
        r = group.random()
        r_2 = group.random() 
        g_r = (pk['g2'] ** r)    
        g_r_2 = (pk['g2'] ** r_2)    
        # D = (mk['g2_alpha'] * g_r_2) ** (1 / mk['beta'])
        pk_cs_r_1 = (pk_cs ** r)
        pk_u_alpha = (pk_u ** mk['alpha'])
        D = (pk_cs_r_1 * pk_u_alpha * g_r_2) ** (1 / mk['beta'])
        D_pr = g_r
        D_j, D_j_pr = {}, {}
        for j in S:
            r_j = group.random()
            D_j[j] = g_r_2 * (group.hash(j, G2) ** r_j)
            D_j_pr[j] = pk['g'] ** r_j
        return { 'D':D, 'Dp':D_pr, 'Dj':D_j, 'Djp':D_j_pr, 'S':S }
       
    @Input(pk_t, GT, str)
    @Output(ct_t)
    def encrypt(self, pk, M, policy_str): 
        policy = util.createPolicy(policy_str)
        a_list = util.getAttributeList(policy)
        s = group.random(ZR)
        shares = util.calculateSharesDict(s, policy)

        C_tilde = (pk['e_gg_alpha'] ** s) * M
        C = pk['h'] ** s
        C_pp = pk['g'] ** s
        
        C_y, C_y_pr = {}, {}
        for i in shares.keys():
            j = util.strip_index(i)
            C_y[i] = pk['g'] ** shares[i]
            C_y_pr[i] = group.hash(j, G2) ** shares[i] 
        
        return { 'C_tilde':C_tilde, 'C':C, 'Cpp':C_pp,
            'Cy':C_y, 'Cyp':C_y_pr, 'policy':policy_str, 'attributes':a_list }

    @Input(pk_t, ZR, sk_t, ct_t)
    @Output(tuple)
    def proxy_decrypt(self, pk, sk_cs, pxy_k_u, ct):
        policy = util.createPolicy(ct['policy'])
        pruned_list = util.prune(policy, pxy_k_u['S'])
        if pruned_list == False:
            return False
        z = util.getCoefficients(policy)
        A = 1 
        for i in pruned_list:
            j = i.getAttributeAndIndex(); k = i.getAttribute()
            A *= ( pair(ct['Cy'][j], pxy_k_u['Dj'][k]) / pair(pxy_k_u['Djp'][k], ct['Cyp'][j]) ) ** z[j]
        
        # return ct['C_tilde'] / (pair(ct['C'], sk['D']) / A)
        e_pkug_s_alpha = pair(ct['C'], pxy_k_u['D']) / (pair(ct['Cpp'], pxy_k_u['Dp']) ** sk_cs * A)
        v = (ct['C_tilde'], e_pkug_s_alpha)
        return v
        
    @Input(pk_t, ZR, tuple)
    @Output(GT)
    def user_decrypt(self, pk, sk_u, v):
        C_tilde = v[0]
        e_pkug_s_alpha = v[1]
        x_u_inverse = sk_u ** (-1)
        m = C_tilde / (e_pkug_s_alpha * x_u_inverse)
        return m


    @Input(pk_t, mk_t, [str])
    @Output(sk_t)
    def keygen(self, pk, mk, S):
        r = group.random() 
        g_r = (pk['g2'] ** r)    
        D = (mk['g2_alpha'] * g_r) ** (1 / mk['beta'])        
        D_j, D_j_pr = {}, {}
        for j in S:
            r_j = group.random()
            D_j[j] = g_r * (group.hash(j, G2) ** r_j)
            D_j_pr[j] = pk['g'] ** r_j
        return { 'D':D, 'Dj':D_j, 'Djp':D_j_pr, 'S':S }

    @Input(pk_t, sk_t, ct_t)
    @Output(GT)
    def decrypt(self, pk, sk, ct):
        policy = util.createPolicy(ct['policy'])
        pruned_list = util.prune(policy, sk['S'])
        if pruned_list == False:
            return False
        z = util.getCoefficients(policy)
        A = 1 
        for i in pruned_list:
            j = i.getAttributeAndIndex(); k = i.getAttribute()
            A *= ( pair(ct['Cy'][j], sk['Dj'][k]) / pair(sk['Djp'][k], ct['Cyp'][j]) ) ** z[j]
        
        return ct['C_tilde'] / (pair(ct['C'], sk['D']) / A)


def main():   
    groupObj = PairingGroup('SS512')

    cpabe = CPabe_BSW07(groupObj)
    attrs = ['ONE', 'TWO', 'THREE']
    access_policy = '((four or three) and (three or one))'
    if debug:
        print("Attributes =>", attrs); print("Policy =>", access_policy)

    (pk, mk) = cpabe.setup()

    # sk = cpabe.keygen(pk, mk, attrs)

    ## START KEY GEN FOR USER & CS
    pk_cs, sk_cs = cpabe.keygen_user(pk)
    if debug: print("\ncloud key pair =>", (pk_cs, sk_cs))
    
    pk_u, sk_u = cpabe.keygen_user(pk)
    if debug: print("\nuser key pair =>", (pk_u, sk_u))

    pxy_k_u = cpabe.keygen_proxy(pk, mk, pk_u, pk_cs, attrs)
    if debug: print("\nproxy key =>", pxy_k_u)

    rand_msg = groupObj.random(GT)
    if debug: print("\nmsg =>", rand_msg)
    ct = cpabe.encrypt(pk, rand_msg, access_policy)
    if debug: print("\nEncrypt...\n", ct)
    groupObj.debug(ct)

    intmed_value = cpabe.proxy_decrypt(pk, sk_cs, pxy_k_u, ct)
    if debug: print("\nPxy Decrypt...\n")
    if debug: print("\nIntm msg =>", intmed_value)

    rec_msg = cpabe.user_decrypt(pk, sk_u, intmed_value)
    if debug: print("\nUser Decrypt...\n")
    if debug: print("\nRec msg =>", rec_msg)

    assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
    if debug: print("\nSuccessful Decryption!!!")
    ## END

if __name__ == "__main__":
    debug = True
    main()
   
