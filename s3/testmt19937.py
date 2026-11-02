from SymmetricCrypto import MT19937 as mt

# Set 3 Challenge 21
# Implemented the MT19937 rng in Python
# GEnerating 20 rng outputs here given seed = 1

rng = mt(1)
# rng.printstate()
for i in range(20):
    print(rng.getrand())

