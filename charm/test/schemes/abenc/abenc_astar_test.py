import unittest

from charm.schemes.abenc.abenc_astar import CPabe_ASTAR
from charm.toolbox.pairinggroup import PairingGroup, GT

## START: Add for the el-gamal support
from charm.toolbox.eccurve import prime192v2
from charm.toolbox.ecgroup import ECGroup
## END

debug = True


class CPabe_ASTARTest(unittest.TestCase):
    def testCPabe_ASTAR(self):
        groupObj = PairingGroup('SS512')

        ## START: Add for the el-gamal support
        groupObj_ec = ECGroup(prime192v2)
        ## END

        ## START: Modify for the el-gamal support
        # cpabe = CPabe_ASTAR(groupObj)
        cpabe = CPabe_ASTAR(groupObj, groupObj_ec)
        ## END

        attrs = ['ONE', 'TWO', 'THREE']
        access_policy = '((four or three) and (three or one))'
        
        if debug:
            print("Attributes =>", attrs)
            print("Policy =>", access_policy)

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
        if debug: print("\nRec msg =>", intmed_value)

        rec_msg = cpabe.user_decrypt(pk, sk_u, intmed_value)
        if debug: print("\nUser Decrypt...\n")
        if debug: print("\nRec msg =>", rec_msg)

        assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
        if debug: print("\nSuccessful Decryption!!!")
        ## END

if __name__ == "__main__":
    unittest.main()
