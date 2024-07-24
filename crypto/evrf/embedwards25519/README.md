# embedwards25519

A curve defined over the Ed25519 scalar field.

This curve was found via
[tevador's script](https://gist.github.com/tevador/4524c2092178df08996487d4e272b096)
for finding curves (specifically, curve cycles), modified to search for curves
whose field is the Ed25519 scalar field (not the Ed25519 field).

```
p = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
q = 0x0fffffffffffffffffffffffffffffffe53f4debb78ff96877063f0306eef96b
D = -420435
y^2 = x^3 - 3*x + 4188043517836764736459661287169077812555441231147410753119540549773825148767
```

The embedding degree is `(q-1)/2`.

This curve should not be used with single-coordinate ladders, and points should
always be represented in a compressed form (preventing receiving off-curve
points).
