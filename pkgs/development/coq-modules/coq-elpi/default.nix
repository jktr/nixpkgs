{ stdenv, fetchFromGitHub, which, coq }:

let params = {
  "8.11" = rec {
    version = "1.4.0";
    rev = "v${version}";
    sha256 = "1pzmjgvvdwki59rfsha3c1ik4gii39j44ijyb9m9as1cyfpxx906";
  };
};
  param = params.${coq.coq-version};
in

stdenv.mkDerivation rec {
  name = "coq${coq.coq-version}-elpi-${param.version}";

  src = fetchFromGitHub {
    owner = "LPCIC";
    repo = "coq-elpi";
    inherit (param) rev sha256;
  };

  nativeBuildInputs = [ which ];
  buildInputs = [ coq coq.ocaml ] ++ (with coq.ocamlPackages; [ findlib elpi ]);

  installFlags = [ "COQLIB=$(out)/lib/coq/${coq.coq-version}/" ];

  meta = {
    description = "Coq plugin embedding ELPI.";
    maintainers = [ stdenv.lib.maintainers.cohencyril ];
    license = stdenv.lib.licenses.lgpl21;
    inherit (coq.meta) platforms;
    inherit (src.meta) homepage;
  };

  passthru = {
    compatibleCoqVersions = stdenv.lib.flip builtins.hasAttr params;
  };
}
