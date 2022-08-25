using Documenter
using AesKeywrapNettle

makedocs(
    sitename = "AesKeywrapNettle",
    format = Documenter.HTML(),
    modules = [AesKeywrapNettle]
)

# Documenter can also automatically deploy documentation to gh-pages.
# See "Hosting Documentation" and deploydocs() in the Documenter manual
# for more information.
#=deploydocs(
    repo = "<repository url>"
)=#
