# Docsy "mostly docs"


This is an example site that uses the [Docsy](https://docsy.dev) Hugo theme.  It's an alternative version of the ["just the docs"](https://github.com/lisaFC/justdocs/) site that uses a documentation page as its home page, which each section also being documentation, rather than starting from `/docs/`.

You can see a preview of this site at https://mostlydocs.netlify.app/

This version does not require a modified copy of the Docsy theme's layouts, so is easier to keep in sync with the Docsy theme. It does this by making use of the [target-specific front matter cascade feature](https://gohugo.io/content-management/front-matter/#front-matter-cascade) that was introduced in Hugo 0.76.0 (with a bug fixed in 0.77.0 that's required for this to work).

If you take a look at `content/en/_index.md`, you'll see:

```yaml
cascade:
- _target:
    path: "/blog/**"
  type: "blog"
  # set to false to include a blog section in the section nav along with docs
  toc_root: true
- _target:
    path: "/**"
    kind: "page"
  type: "docs"
- _target:
    path: "/**"
    kind: "section"
  type: "docs"
```

This makes every page in the site default to the `docs` type, except for `/blog/*` (you could leave this out, of course, or add other sections that you don't want to be treated as `docs`).

The `toc_root` setting causes the `blog` section to be removed from the main section menu in the left bar, and instead show up only when `Blog` is selected from the top menu, making it appear completely separate.

Otherwise it all works just like any other Docsy site.

To use this for yourself, make a copy of this template project and change `content/en` as needed (don't forget to run `git submodule update --init --recursive` to fetch the theme and its dependencies).

## Taxonomy Support

Taxonomies such as tags and categories work in the same way as they do with Docsy.  They are disabled by default. 

See the [Docsy taxonomy support](https://www.docsy.dev/docs/adding-content/taxonomy/) documentation for instructions.
