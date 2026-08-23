# P3 Online/Offline Cost

This experiment distinguishes online latency, offline preprocessing, storage,
communication, and setup assumptions.

## Multiplication Layer

For `m = 16384`, direct comparison with the existing P2 baseline gives:

| Mode | Phone online ms | Reduction vs P2 | Offline/setup | Phone storage | Communication |
| --- | ---: | ---: | --- | ---: | ---: |
| P2 | 12.576 | 1.00x | not separated | 3,145,728 B preprocessing storage | 2,097,152 B |
| P3-A | 13.644 | 0.92x | 43.305 ms phone offline | 1,572,864 B | 2,097,152 B |
| P3-B | 19.082 | 0.66x | 37.930 ms dealer | 1,572,864 B | 2,097,152 B |
| P3-C simulated | 13.753 | 0.91x | 41.205 ms expansion | 32 B before expansion; 1,572,864 B after | 2,097,152 B |

None of the tested P3 modes reaches the required 10x online phone reduction.
The experiment therefore emits:

```text
P3_NO_ONLINE_PHONE_COST_REDUCTION_OVER_P2
P3_PHONE_ONLINE_STILL_LINEAR_IN_MULTIPLICATIONS
```

## Hybrid Toy R1CS

The hybrid experiment replaces the P2 nonlinear multiplication layer with the
P3 variants and keeps the P1-style masked linear transform.

At `(m, N) = (16384, 65536)`:

| Mode | Phone online ms | Server online ms | Offline/setup ms | Phone storage before expansion | Phone storage after expansion | Communication |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| P3-A hybrid | 150.722 | 122.751 | 43.727 phone offline | 7,864,320 B | 7,864,320 B | 4,194,304 B |
| P3-B hybrid | 142.941 | 118.716 | 43.500 dealer | 7,864,320 B | 7,864,320 B | 4,194,304 B |
| P3-C hybrid | 137.171 | 119.188 | 36.213 expansion | 6,291,488 B | 7,864,320 B | 4,194,304 B |

The hybrid remains correct, but it still combines two linear phone costs:

- one cost linear in nonlinear multiplications;
- one correction cost from the masked linear transform.

This keeps the current mainline blocker open.
