import { IdentityPackConformance } from "@pragmatic-tech-ai/todl-identity/testing";
import { LocalIdentityProviderPack } from "../local-identity-provider-pack.js";

IdentityPackConformance.Describe("LocalIdentityProviderPack", () => LocalIdentityProviderPack.Create());
