# un-extractor - an extractor for UN general assembly records

For example:

```bash
un_extractor xml json
```

## Install

### From source code

```
git clone or download the code

# for input data: also clone un-data
git clone git@github.com:un-project/un-data.git ../un-data
```

## Usage

```
un_extractor [options] xml json
```

## Development

Using virtualenv you can create a sandbox in which to develop.

### Python 2

```bash
virtualenv venv
source venv/bin/activate
pip install --upgrade pip setuptools
pip install -r requirements-dev.txt
python un_extractor
```

### Python 3

```bash
virtualenv venv -p /usr/bin/python3
source venv/bin/activate
pip install --upgrade pip setuptools
pip install -r requirements-dev.txt
python un_extractor
```

## License

un-extractor is available under the MIT License. You should find the LICENSE in the root of the project.
