"""
This script updates the README.md file with the list of available algorithms.
"""

import re
from pathlib import Path

PATH_ROOT = Path(__file__).parent
PATH_PQCLEAN = PATH_ROOT / "pqclean"
PATH_README = PATH_ROOT / "README.md"

PQCLEAN_KEM = PATH_PQCLEAN / "crypto_kem"
PQCLEAN_SIGN = PATH_PQCLEAN / "crypto_sign"


def get_algorithms(directory: Path) -> list[str]:
    if not directory.exists():
        return []

    return [
        alg_path.name.replace("-", "_")
        for alg_path in directory.iterdir()
        if alg_path.is_dir()
    ]


def format_algorithm_section(title: str, algorithms: list[str]) -> str:
    if not algorithms:
        return ""

    algorithms.sort()

    section = f"### {title}\n\n"
    section += "```\n"
    for algo in algorithms:
        section += f"- {algo}\n"
    section += "```\n\n"

    return section


def update_readme(
    readme_path: Path, kem_algos: list[str], sign_algos: list[str]
) -> None:
    if not readme_path.exists():
        print(f"README file not found at {readme_path}")
        return

    with open(readme_path, "r") as f:
        content = f.read()

    has_algorithms_section = "## 📋 Available Algorithms" in content

    kem_section = format_algorithm_section("Key Encapsulation Mechanisms", kem_algos)
    sign_section = format_algorithm_section("Signature Algorithms", sign_algos)

    algorithms_section = f"## 📋 Available Algorithms\n\n{kem_section}{sign_section}"

    if has_algorithms_section:
        pattern = r"## 📋 Available Algorithms\n\n(.*?)(?=\n## |$)"
        updated_content = re.sub(pattern, algorithms_section, content, flags=re.DOTALL)
    else:
        pattern = r"(## 🙏 Credits)"
        updated_content = re.sub(pattern, f"{algorithms_section}\\1", content)

    with open(readme_path, "w") as f:
        f.write(updated_content)

    print(
        f"README updated with {len(kem_algos)} KEM and {len(sign_algos)} signature algorithms."
    )


def main() -> None:
    kem_algorithms = get_algorithms(PQCLEAN_KEM)
    sign_algorithms = get_algorithms(PQCLEAN_SIGN)

    if not kem_algorithms and not sign_algorithms:
        print("No algorithms found. Make sure the PQClean directories exist.")
        return

    update_readme(PATH_README, kem_algorithms, sign_algorithms)


if __name__ == "__main__":
    main()
