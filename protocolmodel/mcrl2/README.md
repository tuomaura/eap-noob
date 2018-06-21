# mCRL2 model of EAP-NOOB

This model is based on the latest draft of the [EAP-NOOB](https://datatracker.ietf.org/doc/draft-aura-eap-noob/) protocol and was implemented using the [mCRL2](https://www.mcrl2.org/web/user_manual/index.html) specification language.

## Getting Started

These instructions describe how to compile and test the model.

### Dependencies

The following packages have to be installed before compiling the mCRL2 model:

1. mCRL2 toolkit (available from [the publisher](https://www.mcrl2.org/web/user_manual/download.html#download)) (release version 201409.0)

### Compiling

Compiling the LPS/LTS files using make:

```
$ make (build)
```

Minimising the LTS (optional):

```
$ make conv
```

Deleting old files (\*.trc, \*.lps, \*.lts):

```
$ make clean
```

## Running the tests

The tests are located in [testing/](./testing/) and are executed by the script [test.sh](test.sh).

Running tests:

```
$ make test
```

## Visualising and simulating the model

The model can be visualised and simulated using the mCRL2 toolkit.

2D visualisation (not recommended):

```
$ make graph
```

3D visualisation:

```
$ make view
```

Simulation:

```
$ make sim
```
