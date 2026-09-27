# Data behind the generator

Public data, kept small and compiled into the crate, so that a generated
organization looks like a real one: its people have common names in their
real proportions, and its machines talk to the services real machines talk to.
None of it identifies a person.

| File | What | Source | License |
| --- | --- | --- | --- |
| `given-names.csv` | The 100 most common given names in the United States, with each name's estimated share | FiveThirtyEight, [most-common-name](https://github.com/fivethirtyeight/data/tree/master/most-common-name), from Social Security Administration data | CC BY 4.0 |
| `surnames.csv` | The 300 most common surnames in the United States, with their counts | FiveThirtyEight's copy of the U.S. Census Bureau's surname data, same directory | CC BY 4.0; the Census data is in the public domain |
| `entra-apps.csv` | Application ids and names of Microsoft first-party applications that appear in Entra ID sign-in logs | [merill/microsoft-info](https://github.com/merill/microsoft-info), which collects them from Microsoft Graph and Entra documentation | MIT |
| `m365-endpoints.csv` | Host names of Microsoft 365 services, a network each is served from, and the port | Microsoft's [Office 365 IP address and URL web service](https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service), worldwide instance, fetched 2026-09-27 | Published by Microsoft for configuring networks |

Given names and surnames are drawn independently, weighted by these
frequencies, so a combination such as Maria Garcia is as common as it would
be by chance, and says nothing about anyone who holds it.
