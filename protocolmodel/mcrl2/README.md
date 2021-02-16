# mCRL2 model of EAP-NOOB

A model of the Nimble out-of-band authentication for EAP (EAP-NOOB). Based on version 03 of the [draft](https://datatracker.ietf.org/doc/draft-ietf-emu-eap-noob/).

### Dependencies

- mCRL2 toolkit (release version 202006.0). Available from [the publisher](https://www.mcrl2.org/web/user_manual/download.html).
- Python 3 (for preprocessing & testing)

### Preprocessing and testing

The test cases can be modified in [test.py](test.py) and executed with the Makefile:

```bash
$ make test
```

### Visualizing and simulating the model

2D visualization:

```bash
$ make 2D
```

3D visualization:

```bash
$ make 3D
```

Simulation:

```bash
$ make sim
```

### Error tracing

When an error state is reached, it can be traced:

```bash
$ make trace
```
