# Automating DevSecOps with GHAS Workshop  <!-- omit in toc -->

- Discussed features: secret scanning, Dependabot, and code scanning
- Assumed knowledge: GitHub Actions, git
- Difficulty level: 200

## Contents  <!-- omit in toc -->
- [Requirements and setup instructions](#requirements-and-setup-instructions)
- [Documentation links](#documentation-links)
- [Secret scanning](#secret-scanning)
  - [Enabling secret scanning](#enabling-secret-scanning)
  - [Viewing and managing results](#viewing-and-managing-results)
  - [Introducing a test secret](#introducing-a-test-secret)
  - [Excluding files from secret scanning](#excluding-files-from-secret-scanning)
  - [Managing access to alerts](#managing-access-to-alerts)
- [Dependabot](#dependabot)
  - [Enabling Dependabot alerts](#enabling-dependabot-alerts)
  - [Reviewing the dependency graph](#reviewing-the-dependency-graph)
  - [Viewing and managing results](#viewing-and-managing-results-1)
  - [Enabling Dependabot security updates](#enabling-dependabot-security-updates)
  - [Configuring Dependabot security updates](#configuring-dependabot-security-updates)
  - [Automating Dependabot](#automating-dependabot)
- [Code scanning](#code-scanning)
  - [Enabling code-scanning](#enabling-code-scanning)
  - [Reviewing a failed analysis job](#reviewing-a-failed-analysis-job)
  - [Customizing the build process in the CodeQL workflow](#customizing-the-build-process-in-the-codeql-workflow)
  - [Reviewing and managing results](#reviewing-and-managing-results)
  - [Triaging a result in a PR](#triaging-a-result-in-a-pr)
  - [Customizing CodeQL](#customizing-codeql)
  - [Adding your own code scanning suite to exclude rules](#adding-your-own-code-scanning-suite-to-exclude-rules)
  - [Adding a custom query](#adding-a-custom-query)
  - [Code scanning automation](#code-scanning-automation)

## Requirements and setup instructions

To participate in the workshop you need a GitHub account and need to be invited to the workshop organization [advanced-security](https://github.com/advanced-security).
In the workshop organization create a new project and push a copy of the `octo-gallery` project.

```bash
git clone https://github.com/advanced-security/octo-gallery.git
cd octo-gallery
git remote set-url origin https://github.com/advanced-security/<your project>.git
```

For the REST and GraphQL parts it is recommended to use [Postman](https://www.postman.com/) with our provided collection.

## Documentation links

If you get stuck, try searching our documentation for help and ideas. Below are a few links to help you get started:

- [Configuring notifications for dependabot alerts](https://docs.github.com/en/free-pro-team@latest/github/managing-security-vulnerabilities/configuring-notifications-for-vulnerable-dependencies#configuring-notifications-for-dependabot-alerts)
- [Customizing dependency updates](https://docs.github.com/en/free-pro-team@latest/github/administering-a-repository/customizing-dependency-updates)
- [Dependency update configuration options](https://docs.github.com/en/free-pro-team@latest/github/administering-a-repository/configuration-options-for-dependency-updates)
- [Filter pattern cheat sheet](https://docs.github.com/en/free-pro-team@latest/actions/reference/workflow-syntax-for-github-actions#filter-pattern-cheat-sheet)
- [Configuring code scanning](https://docs.github.com/en/free-pro-team@latest/github/finding-security-vulnerabilities-and-errors-in-your-code/configuring-code-scanning)
- [REST API](https://docs.github.com/en/free-pro-team@latest/rest)
- [GraphQL API](https://docs.github.com/en/free-pro-team@latest/graphql)

## Secret scanning

### _Practical Exercise 1a: Enabling secret scanning_
Secret scanning can be enabled in the settings of an organization or a repository.

1. Go to the repository settings and enable secret scanning in the *Security & analysis* section.

#### Viewing and managing results
After a few minutes, the security tab in the repository will indicate that there are new security alerts.

1. Go to the secret scanning section to view the detected secrets.

For each secret, look at the options to close it and determine which one is most suitable.

#### Introducing a test secret
When developing test cases it might be the case that secrets are introduced that cannot be abused when disclosed. Secret scanning will still detect and alert on these secrets.

1. In the GitHub repository file explorer create a test file that will contain a test secret.
    - For example the file `storage-service/src/main/resources/application.dev.properties` with the secrets
        ```
        aws.accessKeyId=AKIAIOWARUV5O6PE6FKD
        aws.secretKey=C+lTMWVF0=Uk1zrN4iWPBQSzs4NRgn0lMfTpFLqw
        ```
1. Determine if the secret is detected when the file is stored.
1. How would you like to manage results from test files?

#### Excluding files from secret scanning
While we can close a detected secret as being used in a test we can also configure secret scanning to exclude files from being scanned.

1. Create the file `.github/secret_scanning.yml` if it doesn't already exist.
1. Add a list of paths to exclude from secret scanning. You can use [filter patterns](https://docs.github.com/en/free-pro-team@latest/actions/reference/workflow-syntax-for-github-actions#filter-pattern-cheat-sheet) to specify paths.
    ```yaml
    paths-ignore:
        - '**/test'
    ```
    **Note**: The characters `*`, `[`, and `!` are special characters in YAML. If you start a pattern with `*`, `[`, or `!`, you must enclose the pattern in quotes.

    Use a pattern to exclude the file `storage-service/src/main/resources/application.dev.properties`

    <details>
    <summary>Solution</summary>
    A possible solution is:

    ```yaml
    paths-ignore:
        - '**/test'
        - '**/application.dev.properties'
    ```
    </details>

3. Test the pattern by adding another secret or to the file `storage-service/src/main/resources/application.dev.properties`

    For example change the `secretKey` to
    ```
    aws.secretKey=C+lTMWVF0=Uk1zrN4iWPBQSzs4NRgn0lMfTpFLqa
    ```

#### Managing access to alerts
Due to the nature of secrets the alerts are only visible to organization and repository administrators.

Access to other members and teams can be given in the `Security & analysis` setting.

**Note:** The member or teams requires write privileges before access to alerts can be given.

1. To enable this functionality we have to enable Dependabot alerts.
1. In the access to alerts section add another team member or team to provide access to your repository alerts.

## _Practical Exercise 1b: Dependabot_

#### Enabling Dependabot alerts
Dependabot can be enabled in the settings of an organization or a repository.

1. Go to the repository settings and enable Dependabot alerts in the *Security & analysis* section.

#### Reviewing the dependency graph
Dependabot uses the dependency graph to determine which dependencies are used by your project.

1. Verify in the dependency graph that it found dependencies for:
    - The frontend service.
    - The authentication service.
    - The gallery service.
    - The storage service.

The dependency graph can be access in the `Insights` tab in your repository.

#### Viewing and managing results

After a few minutes the security tab will in the repository will indicate that there are new security alerts.

**Note**: If this not the case we can trigger an analysis by updating `authn-service/requirements.txt`

1. Go to the Dependabot alert section to view the detected dependency issues.

For each Dependency alert we have the option to create a scurity update or to dismiss the alert with a reason.

1. For one of the alerts create a Dependency security update. If Dependabot can update the dependency automatically it will create a PR.
1. For one of the alerts dimiss the alert.

#### Enabling Dependabot security updates

Dependabot can automatically create PRs to upgrade vulnerable dependencies to non-vulnerable versions.

1. Go to the repository settings and enable Dependabot security updates in the *Security & analysis* section.

After a few minutes multiple PRs will be created that will upgrade vulnerable dependencies.

#### Configuring Dependabot security updates

To successfully integrate the security updates into the SDLC it is possible to configure various aspects such as:

- When security PRs are created.
- What labels are assigned to enable filtering options.
- Who is assigned to the PR and who should review it.
- Specify which dependency are updated and how they are updated.

1. Create the file `.github/dependabot.yml` in your repository and configure the `pip` dependency manager to.
1. Look for dependency information in the directory `authn-service`.
1. Schedule daily security updates.
1. Prefix the commit message with the package manager `pip`.
1. Assign the PR to yourself and a person from your workshop team as a reviewer.
1. Add the custom label `triage-required` to enable filtering of the PRs (Make sure the label exists by adding it to `https://github.com/advanced-security/<your repo>/labels`).
1. Verify your changes by adding a [vulnerable dependency](https://github.com/advisories?query=severity%3Ahigh+ecosystem%3Apip) to `auth-service/requirements.txt`

    For example
    ```requirements.txt
    ...
    django==2.1.0
    ```
How would you know if the configuration cannot be satisfied?
1. Add a non-existing label to the configuration.
1. Trigger a new Dependabot security update by adding a vulnerable dependency to one of the projects

   For example, we can add the dependency `django-two-factor-auth==1.11` to `auth-service/requirements.txt`
1. Look at the created PR to determine if the configuration is satisfied.

<details>
<summary>Solution</summary>

```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/authn-service"
    schedule:
      interval: "daily"
    labels:
      - "triage-required"
    assignees:
      - "<github handle>"
    reviewers:
      - "<github handle>"
    commit-message:
      prefix: "pip"
```
</details>

#### _Stretch Exercise 1: Automating Dependabot_

For the Dependabot service we have both REST and GraphQL endpoints that allow us to configure aspects and retrieve information.
This can both be used for managing individual repositories at scale or export vulnerability information into other systems used to manage this information in your organization.

**Note** The REST API signals a `404` when you client isn't properly authenticated to limit disclosure of private repositories as outlined [here](https://docs.github.com/en/free-pro-team@latest/rest/overview/troubleshooting#why-am-i-getting-a-404-error-on-a-repository-that-exists). This is the same status code that is returned if features are not enabled.

1. Start by creating a *Personal Access Token* with the `repo` scope and store it for use (e.g., in a Postman environment variable).
1. For your repo, determine if vulnerability alerts are enabled.

   **Hints**
   - [Check if vulnerability alerts are enabled for a repository](https://docs.github.com/en/free-pro-team@latest/rest/reference/repos#check-if-vulnerability-alerts-are-enabled-for-a-repository
   )
   - Since this API is currently available for developers preview we need to use the header `Accept: application/vnd.github.dorian-preview+json`
1. Disable and Enable security updates

   **Hints**
   - [Enable automated security fixes](https://docs.github.com/en/free-pro-team@latest/rest/reference/repos#enable-automated-security-fixes)

<details>
<summary>Solutions</summary>

1. Determining if vulnerability alerts are enabled

    ```bash
    curl --location --request GET 'https://api.github.com/repos/advanced-security/<insert your repo>/vulnerability-alerts' \
    --header 'Accept: application/vnd.github.dorian-preview+json' \
    --header 'Authorization: Bearer <insert your PAT>'
    ```
1. Disabling and enable security updates

    ```bash
    curl --location --request DELETE 'https://api.github.com/repos/advanced-security/<insert your repo>/vulnerability-alerts' \
    --header 'Accept: application/vnd.github.dorian-preview+json' \
    --header 'Authorization: Bearer <insert your PAT>'

    curl --location --request PUT 'https://api.github.com/repos/advanced-security/<insert your repo>/vulnerability-alerts' \
    --header 'Accept: application/vnd.github.dorian-preview+json' \
    --header 'Authorization: Bearer <insert your PAT>'
    ```
</details>

Next we are going to use the GraphQL API to retrieve information on vulnerable dependencies in our repository.

1. Retrieve the `securityVulnerability` objects for your repository.

   If you receive the response, then you need to add the scope `read:org` to your *Personal Access Token*.

   ```json
    {
        "data": {
            "viewer": {
                "organization": null
            }
        }
    }
   ```
   **Hints**
   1. GraphQL is introspective, you can query an object's schema with

        ```graphql
        query {
            __type(name: "SecurityVulnerability") {
                name
                kind
                description
                fields {
                    name
                }
            }
        }
        ```
   1. A [SecurityVulnerability](https://docs.github.com/en/free-pro-team@latest/graphql/reference/objects#securityvulnerability) object can be accessed via the [RepositoryVulnerabilityAlert](https://docs.github.com/en/free-pro-team@latest/graphql/reference/objects#repositoryvulnerabilityalert) object in a [Repository](https://docs.github.com/en/free-pro-team@latest/graphql/reference/objects#repository) object, which itself resides in an [Organization](https://docs.github.com/en/free-pro-team@latest/graphql/reference/objects#organization) object.


<details>
<summary>Solution</summary>

```graphql
query VulnerabilityAlerts($org: String!, $repo: String!){
  viewer {
    organization(login: $org) {
      repository(name: $repo) {
        name
        vulnerabilityAlerts(first: 10) {
          nodes {
            securityVulnerability {
              advisory {
                ghsaId
                description
              }
              package {
                name
                ecosystem
              }
              severity
              firstPatchedVersion {
                identifier
              }
              vulnerableVersionRange
            }
          }
        }
      }
    }
  }
}
```

```bash
curl --location --request POST 'https://api.github.com/graphql' \
--header 'Authorization: Bearer <insert your PAT>' \
--header 'Content-Type: application/json' \
--data-raw '{"query":"query VulnerabilityAlerts($org: String!, $repo: String!){\n  viewer {\n    organization(login: $org) {\n      repository(name: $repo) {\n        name\n        vulnerabilityAlerts(first: 10) {\n          nodes {\n            securityVulnerability {\n              advisory {\n                ghsaId\n                description\n              }\n              package {\n                name\n                ecosystem\n              }\n              severity\n              firstPatchedVersion {\n                identifier\n              }\n              vulnerableVersionRange\n            }\n          }\n        }\n      }\n    }\n  }\n}","variables":{"org":"advanced-security","repo":"<insert your repo>"}}'
```

</details>

## Code scanning

Code scanning enables developers to integrate security analysis tooling into their developing workflow. In this workshop we will focus on the CodeQL static analysis tooling provided by GitHub that helps developers detect common vulnerabilities and coding errors.

### _Practical Exercise 2: Enabling Code scanning_

1. Go to the `Code scanning alerts` section in the `Security` tab.
1. Start the `Set up this workflow` step in the `CodeQL Analysis` card.
1. Review the created Action workflow and accept the default proposed workflow.
1. Head over to the `Actions` tab to see the created workflow in action.

The action failed because the Java job failed.

#### Reviewing a failed analysis job

CodeQL requires a build of compiled languages and an analysis job can fail if our *autobuilder* is unable to build a program to extract an analysis database.

1. Head over to the failed Java job and try to determine the build failure.

   **Hint**: The project is build using Maven so we can search for `Failed to execute goal` in the `Autobuild` step.
1. How would you resolve the build error to ensure the analysis can be performed?

<details>
<summary>Solution</summary>

By default the Action runner is configured with JDK version 1.8, but our project targets JDK version 11.

```bash
Error: 1-05 14:30:13] [autobuild] [ERROR] Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin:3.8.1:compile (default-compile) on project storage-service: Fatal error compiling: invalid target release: 11 -> [Help 1]
```

</details>

#### Customizing the build process in the CodeQL workflow

1. Open the file `.github/workflows/codeql-analysis.yml` for editing in the GitHub repository explorer.
1. Add an appropiate step to configure the Java JDK

    **Hint**: Use the Action marketplace to find an action that can help you.
1. Confirm that java analysis succeeds.

<details>
<summary>Solution</summary>

Add the following step before the `autobuild` step.
```yaml
- name: Setup Java JDK
      uses: actions/setup-java@v1.4.3
      with:
        java-version: 11
```
</details>

#### Reviewing and managing results

1. Go to the `Code scanning results` in the `Security` tab.
1. For a result determine:
    1. The issue reported.
    1. The corresponding query id.
    1. Its `Common Weakness Enumeration` identifier.
    1. The recommendation to solve the issue.
    1. The path from the `source` to the `sink`. Where would you apply a fix?
    1. Is it a *true positive* or *false positive*?

#### Triaging a result in a PR

The default workflow configuration enables code scanning on PRs.
Following the next steps to see it in action.

1. Add a vulnerable snippet of code and commit it to a patch branch and create a PR.

    For make the following change in `frontend/src/components/AuthorizationCallback.vue:27`

    ```javascript
     - if (this.hasCode && this.hasState) {
     + eval(this.code)    
     + if (this.hasCode && this.hasState) {
    ```
1. Is the vulnerability detected in your PR?

#### _Stretch Exercise 2: Using context and expressions to modify build_

How would you [modify](https://docs.github.com/en/free-pro-team@latest/actions/reference/context-and-expression-syntax-for-github-actions) the build such that the Setup JDK step runs only for Java?

  <details>
  <summary>Solution</summary>

  You can run this step for only `Java` analysis when you use the `if` expression and `matrix` context.

  ```yaml
  - if: matrix.language == 'java'  
    uses: actions/setup-java@v1.4.3
    with:
      java-version: 11
  ```
  </details>

#### _Stretch Exercise 3: Fixing False Positive Results_

If you have identified a false positive how would you deal with that? What if this is a common pattern within your applications?

#### _Stretch Exercise 4: Enabling code scanning on your own repository_

So far you've learned how to enable secret scanning, Dependabot and code scanning. Try enabling this on your own repository and see what kind of results you get!

### _Practical Exercise 3: Customizing CodeQL Configuration_

By default CodeQL uses a selection of queries that provide high quality security results.
However, you might want to change this behavior to:

- Include code-quality queries.
- Include queries with a lower signal to noise ratio to detect more potential issues.
- To exclude queries in the default pack because they generate *false positives* for your architecture.
- Include custom queries written for your project.

1.  Create the file `.github/codeql/codeql-config.yml` and enable the `security-and-quality` suite.

    **Hints**

    1. A configuration file contains a key `queries` where you can specify additional queries as follows

        ```yaml
        name: "My CodeQL config"

        queries:
            - uses: <insert your query suite>
        ```
1. Enable your custom configuration in the code scanning workflow file `.github/codeql/codeql-config.yml`

    **Hints**

    1. The `init` action supports a `config-file` parameter to specify a configuration file.
1. After the code scanning action has completed are there new code scanning results?

#### Adding your own code scanning suite to exclude rules

Which queries are execute is determine by the code scanning suite for a target language.
You can create your own code scanning suite to change the set of included queries.

By creating our own code scanning suite we can exclude the rule that caused the false positive in our Java project.

1. Create the file `custom-queries/code-scanning.qls` with the contents

    ```yaml
    # Reusing existing QL Pack
    - import: codeql-suites/javascript-code-scanning.qls
      from: codeql-javascript
    - import: codeql-suites/java-code-scanning.qls
      from: codeql-java
    - import: codeql-suites/python-code-scanning.qls
      from: codeql-python
    - import: codeql-suites/go-code-scanning.qls
      from: codeql-go
    - exclude:
      id:
        - <insert rule id of false positive>
    ```

2. Configure the file `.github/codeql/codeql-config.yml` to use our suite

    **Hint** We are now running both the default code scanning suite and our own custom suite.
    To prevent double results disable the default queries with the option `disable-default-queries: true`
3. After the code scanning action has completed is the false positive still there?

<details>
<summary>Solution</summary>

```yaml
# Reusing existing QL Pack
- import: codeql-suites/javascript-code-scanning.qls
    from: codeql-javascript
- import: codeql-suites/java-code-scanning.qls
from: codeql-java
- import: codeql-suites/python-code-scanning.qls
from: codeql-python
- import: codeql-suites/go-code-scanning.qls
from: codeql-go
- exclude:
    id:
    - java/spring-disabled-csrf-protection
```
</details>

4. Try running additional queries with `security-extended` or `security-and-quality`. What kind of results do you see?

5. Try specifying directories to scan or not to scan. Why would you include this in the configuration?

#### _Stretch Exercise 5: Adding a custom query_

One of the strong suites of CodeQL is its high-level language QL that can be used to write your own queries.
_If you have experience with CodeQL and have come up with your own query so far, take this time to commit those changes and see if any alerts were produced._ 
Regardless of experiencem, the next steps show you how to add one.

1. Create the file `custom-queries/go/qlpack.yml` with the contents

    ```yaml
    name: My Go queries
    version: 0.0.0
    libraryPathDependencies:
        - codeql-go
    ```

    This file creates a [QL query pack](https://help.semmle.com/codeql/codeql-cli/reference/qlpack-overview.html) used to organize query files and their dependencies.
1. Create the file `custom-queries/go/jwt.ql` with the contents

    ```ql
    /**
    * @name Missing token verification
    * @description Missing token verification
    * @id go/user-controlled-bypass
    * @kind problem
    * @problem.severity warning
    * @precision high
    * @tags security
    */
    import go
    /*
    * Identify processors that are missing the token verification:
    *
    * func(token *jwt.Token) (interface{}, error) {
    *    // Don't forget to validate the alg is what you expect:
    *    //if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
    *    //        return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
    *    //}
    *    ...
    * }
    */
    from FuncLit f
    where
        // Identify the function via the argument part of the its signature
        //     func(token *jwt.Token) (interface{}, error) { ... }
        f.getParameter(0).getType() instanceof PointerType and
        f.getParameter(0).getType().(PointerType).getBaseType().getName() = "Token" and
        f.getParameter(0).getType().(PointerType).getBaseType().getPackage().getName() = "jwt" and
        // and check whether it uses jwt.SigningMethodHMAC in any way
        not exists(TypeExpr t |
            f.getBody().getAChild*() = t and
            t.getType().getName() = "SigningMethodHMAC" and
            t.getType().getPackage().getName() = "jwt"
        )
    select f, "This function should be using jwt.SigningMethodHMAC"
    ```
1. Add the query to the CodeQL configuration file `.github/codeql/codeql-config.yml`

    **Hint** The `uses` key accepts repository relative paths.
1. After the code scanning action has completed are there new security results?

#### _Stretch Exercise 5: Code scanning automation_

Like Dependabot our code scanning has a REST api that can be used to retrieve information or modify existing information.

Explorer the options at https://docs.github.com/en/free-pro-team@latest/rest/reference/code-scanning.
