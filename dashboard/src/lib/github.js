const GITHUB_API = "https://api.github.com";
const PER_PAGE = 100;

/**
 * Lists the "owner/repo" full names of every repository the given GitHub
 * access token can see (owned, collaborator, or org-member access) — used to
 * filter compliance scan history down to repos the signed-in user may view.
 */
export async function fetchAccessibleRepoNames(accessToken) {
  const repoNames = new Set();
  let page = 1;

  while (true) {
    const res = await fetch(
      `${GITHUB_API}/user/repos?per_page=${PER_PAGE}&page=${page}&affiliation=owner,collaborator,organization_member`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/vnd.github+json",
        },
        cache: "no-store",
      }
    );

    if (!res.ok) {
      throw new Error(`GitHub API error while listing repos: ${res.status}`);
    }

    const repos = await res.json();
    for (const repo of repos) {
      repoNames.add(repo.full_name);
    }

    if (repos.length < PER_PAGE) break;
    page += 1;
  }

  return repoNames;
}
