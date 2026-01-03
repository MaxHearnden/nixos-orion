{ buildPythonPackage, dnspython, fetchFromGitHub, pyasn1, setuptools }:

buildPythonPackage rec {
  pname = "kdcproxy";
  version = "1.1.0";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "latchset";
    repo = "kdcproxy";
    tag = "v${version}";
    hash = "sha256-uE43fR2PWvfqK7cuvlB4POfro1jZ7asroPQRtIvGyNA=";
  };

  nativeBuildInputs = [ setuptools ];

  propagatedBuildInputs = [ dnspython pyasn1 ];
}
