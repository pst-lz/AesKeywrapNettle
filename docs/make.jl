using Documenter
using AesKeywrapNettle

push!(LOAD_PATH,"../src/")
makedocs(
    sitename = "AesKeywrapNettle.jl Documentation",
    pages = [
        "Index" => "index.md",
        "AesKeywrapNettle" => "AesKeywrapNettle.md",
    ],
    format = Documenter.HTML(prettyurls = false)
)

# Documenter can also automatically deploy documentation to gh-pages.
# See "Hosting Documentation" and deploydocs() in the Documenter manual
# for more information.
deploydocs(
    repo = "github.com/pst-lz/AesKeywrapNettle.jl.git",
    devbranch = "main"
)
