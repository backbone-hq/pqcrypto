import platform
from cffi import FFI
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from typing import Literal, List, Dict, Tuple

AlgorithmType = Literal["kem", "sign"]

PATH_ROOT = Path(__file__).parent
PATH_PQCLEAN = PATH_ROOT / "pqclean"
PATH_PQCRYPTO = PATH_ROOT / "pqcrypto"
PATH_TEMPLATES = PATH_ROOT / "templates"

PQCLEAN_COMMON = PATH_PQCLEAN / "common"
PQCLEAN_KEM = PATH_PQCLEAN / "crypto_kem"
PQCLEAN_SIGN = PATH_PQCLEAN / "crypto_sign"

PQCRYPTO_KEM_C = PATH_PQCRYPTO / "_kem"
PQCRYPTO_SIGN_C = PATH_PQCRYPTO / "_sign"
PQCRYPTO_KEM_PY = PATH_PQCRYPTO / "kem"
PQCRYPTO_SIGN_PY = PATH_PQCRYPTO / "sign"

for directory in [PQCRYPTO_KEM_C, PQCRYPTO_SIGN_C, PQCRYPTO_KEM_PY, PQCRYPTO_SIGN_PY]:
    directory.mkdir(parents=True, exist_ok=True)

for directory in [PATH_PQCRYPTO, PQCRYPTO_KEM_PY, PQCRYPTO_SIGN_PY]:
    package_file = directory / "__init__.py"
    package_file.touch(exist_ok=True)

jinja_environment = Environment(loader=FileSystemLoader(PATH_TEMPLATES))

common_sources: List[Path] = [
    file
    for file in PQCLEAN_COMMON.glob("**/*")
    if file.is_file()
    and file.name.endswith(".c")
    and "keccak" not in str(file.resolve())
]
absolute_common_sources: List[str] = [
    str(source.absolute()) for source in common_sources
]


def prepare_build_args() -> Tuple[List[str], List[str], List[str]]:
    compiler_args, linker_args, libraries = [], [], []

    if platform.system().lower() == "windows":
        compiler_args += ["/O2", "/MD", "/nologo"]
        linker_args += ["/NODEFAULTLIB:MSVCRTD"]
        libraries += ["advapi32"]
    else:
        compiler_args += ["-O3", "-std=c99"]

    return compiler_args, linker_args, libraries


def create_algorithm_ffi(algorithm_name: str, path: str, type: AlgorithmType) -> None:
    base_dir = PQCLEAN_KEM if type == "kem" else PQCLEAN_SIGN
    algorithm_path = base_dir / path
    compiler_args, linker_args, libraries = prepare_build_args()

    variant = "clean"
    variant_path: Path = algorithm_path / variant
    header_path: Path = variant_path / "api.h"

    ffi = FFI()
    definitions_template = jinja_environment.get_template(f"definitions_{type}.c.j2")
    algorithm_id = f"pqclean_{algorithm_name.replace('_', '')}_{variant}".upper()
    definitions = definitions_template.render(algorithm=algorithm_id)
    ffi.cdef(definitions)

    variant_sources = [
        file
        for file in variant_path.glob("**/*")
        if file.is_file() and file.name.endswith(".c")
    ]

    absolute_variant_sources = [str(source.absolute()) for source in variant_sources]
    absolute_header_path = str(header_path.absolute())

    ffi.set_source(
        f"pqcrypto._{type}.{algorithm_name}",
        f'#include "{absolute_header_path}"',
        sources=[*absolute_common_sources, *absolute_variant_sources],
        include_dirs=[str(PQCLEAN_COMMON), str(variant_path.resolve())],
        extra_compile_args=compiler_args,
        extra_link_args=linker_args,
        libraries=libraries,
    )

    ffi.compile(verbose=True)


def define_constants(algorithm_name: str, type: AlgorithmType) -> str:
    variant = "clean"
    algorithm_id = f"pqclean_{algorithm_name.replace('_', '')}_{variant}".upper()
    library_constants: Dict[str, str] = {
        "PUBLIC_KEY_SIZE": f"{algorithm_id}_CRYPTO_PUBLICKEYBYTES",
        "SECRET_KEY_SIZE": f"{algorithm_id}_CRYPTO_SECRETKEYBYTES",
    }

    if type == "kem":
        library_constants.update(
            {
                "CIPHERTEXT_SIZE": f"{algorithm_id}_CRYPTO_CIPHERTEXTBYTES",
                "PLAINTEXT_SIZE": f"{algorithm_id}_CRYPTO_BYTES",
            }
        )
    elif type == "sign":
        library_constants.update(
            {
                "SIGNATURE_SIZE": f"{algorithm_id}_CRYPTO_BYTES",
            }
        )

    lines = [f'ALGORITHM = "{algorithm_name}"']
    lines += [
        f"{const_name} = __lib.{const_value}"
        for const_name, const_value in library_constants.items()
    ]
    return "\n".join(lines)


def create_algorithm_wrapper(algorithm_name: str, type: AlgorithmType) -> None:
    wrapper_dir = PQCRYPTO_KEM_PY if type == "kem" else PQCRYPTO_SIGN_PY
    wrapper_path = wrapper_dir / f"{algorithm_name}.py"
    module_name = f".._{type}.{algorithm_name}"

    variant = "clean"
    algorithm_id = f"pqclean_{algorithm_name.replace('_', '')}_{variant}".upper()
    const_defs: str = define_constants(algorithm_name, type)

    template_name = f"wrapper_{type}.py.j2"
    template = jinja_environment.get_template(template_name)

    wrapper_code = template.render(
        algorithm=algorithm_id, module=module_name, const_defs=const_defs
    )

    with open(wrapper_path, "w") as f:
        f.write(wrapper_code)


def main() -> None:
    for alg_path in PQCLEAN_KEM.iterdir():
        if alg_path.is_dir():
            alg_name = f"{alg_path.name}".replace("-", "_")
            path = alg_path.name
            create_algorithm_ffi(alg_name, path, "kem")
            create_algorithm_wrapper(alg_name, "kem")

    for alg_path in PQCLEAN_SIGN.iterdir():
        if alg_path.is_dir():
            alg_name = f"{alg_path.name}".replace("-", "_")
            path = alg_path.name
            create_algorithm_ffi(alg_name, path, "sign")
            create_algorithm_wrapper(alg_name, "sign")


if __name__ == "__main__":
    main()
