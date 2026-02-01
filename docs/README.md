# CodeMind Documentation

This folder contains the CodeMind documentation website, hosted on GitHub Pages.

## Local Development

```bash
cd docs
python -m http.server 8080
# Open http://localhost:8080
```

## GitHub Pages Setup

1. Go to repository Settings → Pages
2. Source: Deploy from a branch
3. Branch: `main` → `/docs` folder
4. Save

The site will be available at: `https://szymonsowula.github.io/codemind/`

## Custom Domain (Optional)

To use a custom domain:

1. Add your domain to the CNAME file
2. Configure DNS records with your domain provider:
   - CNAME record: `www` → `szymonsowula.github.io`
   - A records for apex domain:
     - 185.199.108.153
     - 185.199.109.153
     - 185.199.110.153
     - 185.199.111.153
3. Enable "Enforce HTTPS" in GitHub Pages settings
