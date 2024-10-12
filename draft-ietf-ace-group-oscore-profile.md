---
v: 3

title:  The Group Object Security for Constrained RESTful Environments (Group OSCORE) Profile of the Authentication and Authorization for Constrained Environments (ACE) Framework
abbrev: Group OSCORE Profile of ACE
docname: draft-ietf-ace-group-oscore-profile-latest


# stand_alone: true

ipr: trust200902
area: Security
wg: ACE Working Group
kw: Internet-Draft
cat: std
submissiontype: IETF

coding: utf-8

author:
      -
        ins: M. Tiloca
        name: Marco Tiloca
        org: RISE AB
        street: Isafjordsgatan 22
        city: Kista
        code: SE-16440 Stockholm
        country: Sweden
        email: marco.tiloca@ri.se
      -
        ins: R. Höglund
        name: Rikard Höglund
        org: RISE AB
        street: Isafjordsgatan 22
        city: Kista
        code: SE-16440 Stockholm
        country: Sweden
        email: rikard.hoglund@ri.se
      -
        ins: F. Palombini
        name: Francesca Palombini
        org: Ericsson AB
        street: Torshamnsgatan 23
        city: Kista
        code: SE-16440 Stockholm
        country: Sweden
        email: francesca.palombini@ericsson.com


normative:
  I-D.ietf-core-groupcomm-bis:
  I-D.ietf-core-oscore-groupcomm:
  I-D.ietf-ace-key-groupcomm-oscore:
  RFC5246:
  RFC5705:
  RFC5869:
  RFC6347:
  RFC6749:
  RFC7252:
  RFC7748:
  RFC8392:
  RFC8610:
  RFC8613:
  RFC8447:
  RFC8747:
  RFC8949:
  RFC9052:
  RFC9053:
  RFC9200:
  RFC9201:
  RFC9203:
  NIST-800-56A:
    author:
      -
        ins: E. Barker
        name: Elaine Barker
      -
        ins: L. Chen
        name: Lily Chen
      -
        ins: A. Roginsky
        name: Allen Roginsky
      -
        ins: A. Vassilev
        name: Apostol Vassilev
      -
        ins: R. Davis
        name: Richard Davis
    title: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography - NIST Special Publication 800-56A, Revision 3
    date: 2018-04
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf

informative:
  I-D.tiloca-core-oscore-discovery:
  I-D.ietf-cose-cbor-encoded-cert:
  I-D.ietf-ace-edhoc-oscore-profile:
  I-D.ietf-ace-workflow-and-params:
  RFC5280:
  RFC8446:
  RFC9147:
  RFC9202:
  RFC9431:
  NIST-800-207:
    author:
      -
        ins: S. Rose
        name: Scott Rose
      -
        ins: O. Borchert
        name: Oliver Borchert
      -
        ins: S. Mitchell
        name: Stu Mitchell
      -
        ins: S. Connelly
        name: Sean Connelly
    title: Zero Trust Architecture - NIST Special Publication 800-207
    date: 2020-08
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf

entity:
  SELF: "[RFC-XXXX]"

--- abstract

This document specifies a profile for the Authentication and Authorization for Constrained Environments (ACE) framework. The profile uses Group Object Security for Constrained RESTful Environments (Group OSCORE) to provide communication security between a client and one or multiple resource servers that are members of an OSCORE group. The profile securely binds an OAuth 2.0 access token to the public key of the client associated with the private key used by that client in the OSCORE group. The profile uses Group OSCORE to achieve server authentication, as well as proof-of-possession for the client's public key. Also, it provides proof of the client's membership to the OSCORE group by binding the access token to information from the Group OSCORE Security Context, thus allowing the resource server(s) to verify the client's membership upon receiving a message protected with Group OSCORE from the client. Effectively, the profile enables fine-grained access control paired with secure group communication, in accordance with the Zero Trust principles.

--- middle

# Introduction # {#intro}

A number of applications rely on a group communication model where a client can access a resource hosted by multiple resource servers at once, e.g., over IP multicast. Typical examples include switching of luminaries, actuators control, and distribution of software updates. Secure communication in the group can be achieved by sharing a set of keying material, which is typically provided upon joining the group.

For some of such applications, it may be just fine to enforce access control in a straightforward fashion. That is, any client authorized to join the group, hence to obtain the group keying material, can be also implicitly authorized to perform any action at any resource of any server in the group. An example of application where such implicit authorization might serve well is a simple lighting scenario, where the lightbulbs are the servers, while the user account on an app on the user's phone is the client. In this case, it might be fine to not require additional authorization evidence from any user account, if it is acceptable that any current group member is also authorized to switch on and off any light, or to check the status of any light.

However, in different instances of such applications, the approach above is not desirable, as different group members are intended to have different access rights to resources of other group members. For instance, enforcing access control in accordance with a more fine-grained approach is required in the two following use cases.

As a first case, an application provides control of smart locks acting as servers in the group, where: a first type of client, e.g., a user account of a child, is allowed to only query the status of the smart locks; while a second type of client, e.g., a user account of a parent, is allowed to both query and change the status of the smart locks. Further similar applications concern the enforcement of different sets of permissions in groups with sensor/actuator devices, e.g., thermostats acting as servers. Also, some group members may even be intended as servers only. Hence, they must be prevented from acting as clients altogether and from accessing resources at other servers in the group, especially when attempting to perform non-safe operations.

As a second case, building automation scenarios often rely on servers that, under different circumstances, enforce different level of priority for processing received commands. For instance, BACnet deployments consider multiple classes of clients, e.g., a normal light switch (C1) and an emergency fire panel (C2). Then, a C1 client is not allowed to override a command from a C2 client, until the latter relinquishes control at its higher priority. That is: i) only C2 clients should be able to adjust the minimum required level of priority on the servers, so rightly locking out C1 clients if needed; and ii) when a server is set to accept only high-priority commands, only C2 clients should be able to perform such commands otherwise allowed also to C1 clients. Given the different maximum authority of different clients, fine-grained access control would effectively limit the execution of high- and emergency-priority commands only to devices that are in fact authorized to perform such actions. Besides, it would prevent a misconfigured or compromised device from initiating a high-priority command and lock out normal control.

In the cases above, being a legitimate group member and storing the group keying material is not supposed to imply any particular access rights. Instead, access control to the secure group communication channel and access control to the resource space provided by servers in the group should remain logically separated domains.

This is aligned with the Zero Trust paradigm {{NIST-800-207}}, which focuses on resource protection and builds on the premise that trust is never granted implicitly, but must be continually evaluated. In particular, Zero Trust protections involve "minimizing access to resources (such as data and compute resources and applications/services) to only those subjects and assets identified as needing access as well as continually authenticating and authorizing the identity and security posture of each access request."

Furthermore, {{NIST-800-207}} highlights how the Zero Trust goal is to "prevent unauthorized access to data and services coupled with making the access control enforcement as granular as possible", to "enforce least privileges needed to perform the action in the request."

As a step in this direction, one can be tempted to introduce a different security group for each different set of access rights. However, this inconveniently results in additional keying material to distribute and manage. In particular, if the access rights pertaining to a node change, this requires to evict the node from the group, after which the node has to join a different group aligned with its new access rights. Moreover, the keying material of both groups would have to be renewed for their current members. Overall, this would have a non negligible impact on operations and performance.

Instead, a fine-grained yet flexible access control model can be enforced within the same group, by using the Authentication and Authorization for Constrained Environments (ACE) framework {{RFC9200}}. That is, a client has to first obtain authorization credentials in the form of an access token, and upload it to the intended resource server(s) in the group before accessing the target resources hosted therein.

The ACE framework delegates to separate profile documents how to secure communications between the client and the resource servers. However each of the current profiles of ACE defined in {{RFC9202}}{{RFC9203}}{{RFC9431}}{{I-D.ietf-ace-edhoc-oscore-profile}} relies on a security protocol that cannot be used to protect one-to-many group messages, for example sent over IP multicast.

This document specifies the "coap_group_oscore" profile of the ACE framework, where a client uses the Constrained Application Protocol (CoAP) {{RFC7252}}{{I-D.ietf-core-groupcomm-bis}} to communicate with one or multiple resource servers that are members of an application group and share a common set of resources. This profile uses Group Object Security for Constrained RESTful Environments (Group OSCORE) {{I-D.ietf-core-oscore-groupcomm}} as the security protocol to protect messages exchanged between the client and the resource servers. Hence, it requires that both the client and the resource servers have previously joined the same OSCORE group.

That is, this profile describes how access control is enforced for a client after it has joined an OSCORE group, to access resources hosted by other members in that group. The process for joining the OSCORE group through the respective Group Manager as defined in {{I-D.ietf-ace-key-groupcomm-oscore}} takes place before the process described in this document, and is out of the scope of this profile.

The client proves its access to be authorized to the resource server(s) by using an access token bound to a key (the proof-of-possession key). This profile uses Group OSCORE to achieve server authentication and proof-of-possession for the client's public key used in the OSCORE group in question. Note that proof-of-possession is not achieved through a dedicated protocol element, but instead after the first message exchange protected with Group OSCORE.

Furthermore, this profile provides proof of the client's membership to the OSCORE group, by binding the access token to information from the pre-established Group OSCORE Security Context, as well as to the client's authentication credential used in the group and including the client's public key. This allows the resource server(s) to verify the client's group membership upon reception of a message protected with Group OSCORE from that client.

OSCORE {{RFC8613}} specifies how to use COSE {{RFC9052}}{{RFC9053}} to secure CoAP messages. Group OSCORE builds on OSCORE to provide secure group communication, and ensures source authentication: by means of digital signatures embedded in the protected message (when using the group mode); or by protecting a message with pairwise keying material derived from the asymmetric keys of the two peers exchanging the message (when using the pairwise mode).

## Terminology ## {#terminology}

{::boilerplate bcp14-tagged}

Readers are expected to be familiar with the terms and concepts related to CBOR {{RFC8949}}, COSE {{RFC9052}}{{RFC9053}}, CoAP {{RFC7252}}, OSCORE {{RFC8613}}, and Group OSCORE {{I-D.ietf-core-oscore-groupcomm}}. These especially include:

* Group Manager, as the entity responsible for a set of groups where communications among members are secured with Group OSCORE.

* Authentication credential, as the set of information associated with an entity, including that entity's public key and parameters associated with the public key. Examples of authentication credentials are CBOR Web Tokens (CWTs) and CWT Claims Sets (CCSs) {{RFC8392}}, X.509 certificates {{RFC5280}}, and C509 certificates {{I-D.ietf-cose-cbor-encoded-cert}}.

   Members of an OSCORE group have an associated authentication credential in the format used within the group. As per {{Section 2.4 of I-D.ietf-core-oscore-groupcomm}}, an authentication credential provides the public key as well as the comprehensive set of information related to the public key algorithm, including, e.g., the used elliptic curve (when applicable).

Readers are also expected to be familiar with the terms and concepts described in the ACE framework for authentication and authorization {{RFC9200}}, as well as in the OSCORE profile of ACE {{RFC9203}}. The terminology for entities in the considered architecture is defined in OAuth 2.0 {{RFC6749}}. In particular, this includes client (C), resource server (RS), and authorization server (AS).

Note that the term "endpoint" is used here following its OAuth definition {{RFC6749}}, aimed at denoting resources such as /token and /introspect at the AS, and /authz-info at the RS. This document does not use the CoAP definition of "endpoint", which is "An entity participating in the CoAP protocol".

Additionally, this document makes use of the following terminology.

* Pairwise-only group: an OSCORE group that uses only the pairwise mode of Group OSCORE (see {{Section 8 of I-D.ietf-core-oscore-groupcomm}}).

Examples throughout this document are expressed in CBOR diagnostic notation as defined in {{Section 8 of RFC8949}} and {{Section G of RFC8610}}. Diagnostic notation comments are often used to provide a textual representation of the parameters' keys and values.

In the CBOR diagnostic notation used in this document, constructs of the form e'SOME_NAME' are replaced by the value assigned to SOME_NAME in the CDDL model shown in {{fig-cddl-model}} of {{sec-cddl-model}}. For example, {e'context_id_param': h'abcd0000', e'salt_input_param': h'00} stands for {71: h'abcd0000', 72: h'00}.

Note to RFC Editor: Please delete the paragraph immediately preceding this note. Also, in the CBOR diagnostic notation used in this document, please replace the constructs of the form e'SOME_NAME' with the value assigned to SOME_NAME in the CDDL model shown in {{fig-cddl-model}} of {{sec-cddl-model}}. Finally, please delete this note.

# Protocol Overview # {#sec-protocol-overview}

This section provides an overview of this profile, i.e., of how to use the ACE framework for authentication and authorization {{RFC9200}} to secure communications between a client and one or more resource servers using Group OSCORE {{I-D.ietf-core-oscore-groupcomm}}.

Note that this profile of ACE describes how access control can be enforced for a node after it has joined an OSCORE group, to access resources hosted by other members in that group.

In particular, the process of joining the OSCORE group through the respective Group Manager as defined in {{I-D.ietf-ace-key-groupcomm-oscore}} must take place before the process described in this document, and is out of the scope of this profile.

An overview of the protocol flow for this profile is shown in {{fig-protocol-overview}}, where it is assumed that both the resource servers RS1 and RS2 are associated with the same authorization server AS. It is also assumed that the client C, as well as RS1 and RS2 have previously joined an OSCORE group with Group Identifier (gid) 0xabcd0000, and that they got assigned Sender ID (sid) 0x00, 0x01, and 0x02 in the group, respectively. The names of messages coincide with those of {{RFC9200}} when applicable, and messages in square brackets are optional.

~~~~~~~~~~~ aasvg
C                             RS1         RS2                        AS
|                              |           |                          |
| [--- Resource Request ---->] |           |                          |
|                              |           |                          |
| [<------ AS Request -------] |           |                          |
|       Creation Hints         |           |                          |
|                              |           |                          |
+-------- POST /token ----------------------------------------------->|
|   (aud: "RS1", sid: 0x00,    |           |                          |
|    gid: 0xabcd0000, ...)     |           |                          |
|                              |           |                          |
|<---------------------------------------------- Access token T1 -----+
|                              |               + Access Information   |
|                              |           |                          |
+----- POST /authz-info ------>|           |                          |
|     (access_token: T1)       |           |                          |
|                              |           |                          |
|<------- 2.01 Created --------+           |                          |
|                              |           |                          |
+-------- POST /token ----------------------------------------------->|
|   (aud: "RS2", sid: 0x00,    |           |                          |
|    gid: 0xabcd0000, ...)     |           |                          |
|                              |           |                          |
|<---------------------------------------------- Access token T2 -----+
|                              |               + Access Information   |
|                              |           |                          |
+----- POST /authz-info ------------------>|                          |
|     (access_token: T2)       |           |                          |
|                              |           |                          |
|<------ 2.01 Created ---------------------+                          |
|                              |           |                          |
+-- Group OSCORE Request --+-->|           |                          |
|    (kid: 0x00,            \  |           |                          |
|     gid: 0xabcd0000)       \ |           |                          |
|                             `----------->|                          |
|                              |           |                          |
|                           /proof-of-possession/                     |
|                              |           |                          |
|<--- Group OSCORE Response ---+           |                          |
|        (kid: 0x01)           |           |                          |
|                              |           |                          |
/proof-of-possession/          |           |                          |
|                              |           |                          |
|                              |           |                          |
/Mutual authentication         |           |                          |
 between C and RS1/            |           |                          |
|                              |           |                          |
|<--- Group OSCORE Response ---------------+                          |
|        (kid: 0x02)           |           |                          |
|                              |           |                          |
/proof-of-possession/          |           |                          |
|                              |           |                          |
|                              |           |                          |
/Mutual authentication         |           |                          |
 between C and RS2/            |           |                          |
|                              |           |                          |
|            ...               |           |                          |
|                              |           |                          |
~~~~~~~~~~~
{: #fig-protocol-overview title="Protocol Overview." artwork-align="center"}

## Pre-Conditions ## {#sec-protocol-overview-pre-conditions}

Using Group OSCORE and this profile requires that both the client and the resource servers have previously joined the same OSCORE group. This especially includes the derivation of the Group OSCORE Security Context and the assignment of unique Sender IDs to use in the group. Nodes can join the OSCORE group through the respective Group Manager by using the approach defined in {{I-D.ietf-ace-key-groupcomm-oscore}}, which is also based on ACE.

After the client and resource servers have joined the group, this profile provides access control for accessing resources on those resource servers, by securely communicating with Group OSCORE.

As a pre-requisite for this profile, the client has to have successfully joined the OSCORE group where also the resource servers (RSs) are members. Depending on the limited information initially available, the client may have to first discover the exact OSCORE group used by the RSs for the resources of interest, e.g., by using the approach defined in {{I-D.tiloca-core-oscore-discovery}}.

## Requesting an Access Token ## {#sec-protocol-overview-token-retrieval}

This profile requires that the client requests an access token from the AS for the resource(s) that it wants to access at the RS(s), by using the /token endpoint as specified in {{Section 5.8 of RFC9200}}.

In general, different RSs can be associated with different ASs, even if the RSs are members of the same OSCORE group. However, assuming proper configurations and trust relations, it is possible for multiple RSs associated with the same AS to be part of a single audience (i.e., a group-audience, see {{Section 6.9 of RFC9200}}). In such a case, the client can request a single access token intended for the group-audience, hence to all the RSs included therein. A particular group-audience might be defined as including all the RSs in the OSCORE group.

In the Access Token Request to the AS, the client MUST include the Group Identifier of the OSCORE group and its own Sender ID in that group. The AS MUST specify these pieces of information in the access token.

Furthermore, in the Access Token Request to the AS, the client MUST also include: its own authentication credential used in the OSCORE group; and a proof-of-possession (PoP) evidence to prove possession of the corresponding private key to the AS. The PoP evidence is computed over a PoP input uniquely related to the secure communication association between the client and the AS. The AS MUST include also the authentication credential specified by the client in the access token.

If the request from the client is granted, then the AS can send back the issued access token in the Access Token Response to the client, or instead upload the access token directly to the RS as described in the alternative workflow defined in {{I-D.ietf-ace-workflow-and-params}}. This document focuses on the former option (also shown in the example in {{fig-protocol-overview}}), while the latter option is not detailed further here.

The Access Token Request and Response exchanged between the client and the AS MUST be confidentiality-protected and ensure authenticity. In this profile, it is RECOMMENDED to use OSCORE {{RFC8613}} between the client and the AS, to reduce the number of libraries that the client has to support. Other protocols fulfilling the security requirements defined in {{Sections 5 and 6 of RFC9200}} MAY alternatively be used, such as TLS {{RFC8446}} or DTLS {{RFC9147}}.

## Access Token Uploading ## {#sec-protocol-overview-token-posting}

After having retrieved the access token from the AS, the client uploads the access token to the RS, by sending a POST request to the /authz-info endpoint and using the mechanisms specified in {{Section 5.10 of RFC9200}}. When using this profile, the communication that C has with the /authz-info endpoint is not protected.

If the access token is valid, the RS replies to the POST request with a 2.01 (Created) response. Also, the RS associates the received access token with the Group OSCORE Security Context identified by the Group Identifier specified in the access token (see {{Section 2.1.3 of I-D.ietf-core-oscore-groupcomm}}). In practice, the RS maintains a collection of Security Contexts with associated authorization information, for all the clients that it is currently communicating with. The authorization information is a policy that is used as input when processing requests from those clients.

Finally, the RS stores the association between i) the authorization information from the access token; and ii) the Group Identifier of the OSCORE group together with the Sender ID and the authentication credential of the client in that group (see {{Section 2 of I-D.ietf-core-oscore-groupcomm}}). This binds the access token to the Group OSCORE Security Context of the OSCORE group.

Finally, when the client communicates with the RS using the Group OSCORE Security Context, the RS verifies that the client is a legitimate member of the OSCORE group and especially the exact group member with the same Sender ID associated with the access token. This occurs when verifying a request protected with Group OSCORE, since the request includes the client's Sender ID and either it embeds a signature computed also over that Sender ID (if protected with the group mode), or it is protected by means of pairwise symmetric keying material derived from the asymmetric keys of the two peers (if protected with the pairwise mode).

The above has considered an access token intended for a single RS. However, as discussed in {{sec-protocol-overview-token-retrieval}}, an access token can be intended for a group-audience including multiple RSs in the OSCORE group. In such a case, the client could efficiently upload the access token to many or all of those RSs at once (e.g., over IP multicast), after which each RS individually performs the same steps described above.

## Secure Communication ## {#sec-protocol-overview-communication}

The client can send a request protected with Group OSCORE {{I-D.ietf-core-oscore-groupcomm}} to the RS. This can be a unicast request targeting the RS, or a one-to-many group request (e.g., over IP multicast) targeting the OSCORE group where the RS is also a member. To this end, the client uses the Group OSCORE Security Context already established upon joining the OSCORE group, e.g., by using the approach defined in {{I-D.ietf-ace-key-groupcomm-oscore}}. The RS may send a response back to the client, protecting it by means of the same Group OSCORE Security Context.

# Client-AS Communication # {#sec-c-as-comm}

This section details the Access Token POST Request that the client sends to the /token endpoint of the AS, as well as the related Access Token Response.

The access token MUST be bound to the public key of the client as proof-of-possession key (pop-key), which is included in the client's authentication credential specified in the 'cnf' claim of the access token.

## C-to-AS: POST to Token Endpoint ## {#sec-c-as-token-endpoint}

The Client-to-AS request is specified in {{Section 5.8.1 of RFC9200}}. The client MUST send this POST request to the /token endpoint over a secure channel that guarantees authentication, message integrity, and confidentiality.

The POST request is formatted as the analogous Client-to-AS request in the OSCORE profile of ACE (see {{Section 3.1 of RFC9203}}), with the following additional parameters that MUST be included in the payload.

* 'context_id', defined in {{context_id}} of this document. This parameter specifies the Group Identifier (GID), i.e., the ID Context of an OSCORE group that includes as members both the client and the RS(s) in the audience for which the access token is asked to be issued. In particular, the client wishes to communicate with the RS(s) in that audience using the Group OSCORE Security Context associated with that OSCORE group.

* 'salt_input', defined in {{salt_input}} of this document. This parameter includes the Sender ID that the client has in the OSCORE group whose GID is specified in the 'context_id' parameter above.

* 'req_cnf', defined in {{Section 3.1 of RFC9201}}. This parameter follows the syntax from {{Section 3.1 of RFC8747}}, and its inner confirmation value specifies the authentication credential that the client uses in the OSCORE group. The public key included in the authentication credential will be used as the pop-key bound to the access token.

   At the time of writing this specification, acceptable formats of authentication credentials in Group OSCORE are CBOR Web Tokens (CWTs) and CWT Claims Sets (CCSs) {{RFC8392}}, X.509 certificates {{RFC5280}}, and C509 certificates {{I-D.ietf-cose-cbor-encoded-cert}}.

   Further formats may be available in the future, and would be acceptable to use as long as they comply with the criteria compiled in {{Section 2.4 of I-D.ietf-core-oscore-groupcomm}}. In particular, an authentication credential has to explicitly include the public key as well as the comprehensive set of information related to the public key algorithm, including, e.g., the used elliptic curve (when applicable).

   \[ As to CWTs and CCSs, the CWT Confirmation Methods 'kcwt' and 'kccs' are under pending registration requested by draft-ietf-ace-edhoc-oscore-profile. \]

   \[ As to X.509 certificates, the CWT Confirmation Methods 'x5bag' and '5chain' are under pending registration requested by draft-ietf-ace-edhoc-oscore-profile. \]

   \[ As to C509 certificates, the CWT Confirmation Methods 'c5b'and 'c5c' are under pending registration requested by draft-ietf-ace-edhoc-oscore-profile. \]

In addition, the client computes its proof-of-possession (PoP) evidence, in order to prove to the AS the possession of its own private key used in the OSCORE group. This allows the AS to verify that the client indeed owns the private key associated with the public key of the authentication credential that the client allegedly uses in the OSCORE group.

To this end, the client MUST use as PoP input the byte representation of an information that uniquely represents the secure communication association between the client and the AS. It is RECOMMENDED that the client uses the following as PoP input.

* If the client and the AS communicate over TLS 1.2 {{RFC5246}} or DTLS 1.2 {{RFC6347}}, the PoP input is an exporter value computed as defined in {{Section 4 of RFC5705}}, using the following inputs:

   - The exporter label "EXPORTER-ACE-PoP-Input-Client-AS", defined in {{iana-tls-exporter-label}} of this document.

   - The empty 'context value', i.e., a 'context value' of zero-length.

   - 32 as length value in bytes.

* If the client and the AS communicate over TLS 1.3 {{RFC8446}} or DTLS 1.3 {{RFC9147}}, the PoP input is an exporter value computed as defined in {{Section 7.5 of RFC8446}}, using the following inputs:

   - The exporter label "EXPORTER-ACE-PoP-Input-Client-AS", defined in {{iana-tls-exporter-label}} of this document.

   - The empty 'context_value', i.e., a 'context_value' of zero-length.

   - 32 as 'key_length' in bytes.

* If the client and the AS communicate over OSCORE {{RFC8613}}, the PoP input is the output PRK of an HKDF-Extract step {{RFC5869}}, i.e., PRK = HMAC-Hash(salt, IKM).

   In particular, given the OSCORE Security Context CTX shared between the client and the AS, then the following applies.

  - 'salt' takes (x1 \| x2), where \| denotes byte string concatenation, while x1 and x2 are defined as follows.

    - x1 is the binary representation of a CBOR data item. If CTX does not specify an OSCORE ID Context, the CBOR data item is the CBOR simple value `null` (0xf6). Otherwise, the CBOR data item is a CBOR byte string, with value the OSCORE ID Context specified in CTX.

    - x2 is the binary representation of a CBOR byte string. The value of the CBOR byte string is the OSCORE Sender ID of the client, which the client stores in its Sender Context of CTX and the AS stores in its Recipient Context of CTX.

  - 'IKM' is the OSCORE Master Secret specified in CTX.

  - The used HKDF is the HKDF Algorithm specified in CTX.

  The following shows an example of input to the HMAC-Hash() function.

  On the client side, the OSCORE Security Context shared with the AS includes:

  ~~~~~~~~~~~
  ID Context: 0x37cbf3210017a2d3 (8 bytes)

  Sender ID: 0x01 (1 byte)

  Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
  ~~~~~~~~~~~

  Then, the following holds.

  ~~~~~~~~~~~
  x1 (Raw value) (8 bytes)
  0x37cbf3210017a2d3

  x1 (CBOR Data Item) (9 bytes)
  0x4837cbf3210017a2d3

  x2 (Raw value) (1 bytes)
  0x01

  x2 (CBOR Data Item) (2 bytes)
  0x4101

  salt (11 bytes)
  0x4837cbf3210017a2d34101

  IKM (16 bytes)
  0x0102030405060708090a0b0c0d0e0f10
  ~~~~~~~~~~~

After that, the client computes the PoP evidence as follows.

- If the OSCORE group is not a pairwise-only group, the PoP evidence MUST be a signature. The client computes the signature by using the same private key and signature algorithm it uses for signing messages in the OSCORE group. The client's private key is the one associated with the client's authentication credential used in the OSCORE group and specified in the 'req_cnf' parameter above.

- If the OSCORE group is a pairwise-only group, the PoP evidence MUST be a MAC computed as follows, by using the HKDF Algorithm HKDF SHA-256, which consists of composing the HKDF-Extract and HKDF-Expand steps {{RFC5869}}.

    MAC = HKDF(salt, IKM, info, L)

    The input parameters of HKDF are as follows.

    * salt takes as value the empty byte string.

    * IKM is computed as a cofactor Diffie-Hellman shared secret (see Section 5.7.1.2 of {{NIST-800-56A}}), using the ECDH algorithm that is used as Pairwise Key Agreement Algorithm in the OSCORE group. The client uses its own Diffie-Hellman private key and the Diffie-Hellman public key of the AS. For X25519 and X448, the procedure is described in {{Section 5 of RFC7748}}.

       The client's private key is the one associated with the client's authentication credential used in the OSCORE group and specified in the 'req_cnf' parameter above. The client may obtain the Diffie-Hellman public key of the AS during its registration process at the AS.

    * info takes as value the PoP input.

    * L is equal to 8, i.e., the size of the MAC, in bytes.

Finally, the client MUST include one of the two following parameters in the payload of the POST request to the AS.

* 'client_cred_verify', defined in {{client_cred_verify}} of this document, specifying the client's PoP evidence as a signature, which is computed as defined above. This parameter MUST be included if and only if the OSCORE group is not a pairwise-only group.

* 'client_cred_verify_mac', defined in {{client_cred_verify_mac}} of this document, specifying the client's PoP evidence as a MAC, which is computed as defined above. This parameter MUST be included if and only if the OSCORE group is a pairwise-only group.

An example of such a request is shown in {{fig-example-C-to-AS-symm}}.

~~~~~~~~~~~
Header: POST (Code=0.02)
Uri-Host: "as.example.com"
Uri-Path: "token"
Content-Format: 19 (application/ace+cbor)
Payload:
{
  / audience /        5 : "tempSensor4711",
  / scope /           9 : "read",
    e'context_id_param' : h'abcd0000',
    e'salt_input_param' : h'00',
  e'client_cred_verify' : h'c5a6...f100' / elided for brevity /,
  / req_cnf /         4 : {
    e'kccs' : {
      / sub / 2 : "42-50-31-FF-EF-37-32-39",
      / cnf / 8 : {
        / COSE_Key / 1 : {
          / kty /  1 : 2 / EC2 /,
          / crv / -1 : 1 / P-256 /,
          / x /   -2 : h'd7cc072de2205bdc1537a543d53c60a6
                         acb62eccd890c7fa27c9e354089bbe13',
          / y /   -3 : h'f95e1d4b851a2cc80fff87d8e23f22af
                         b725d535e515d020731e79a3b4e47120'
        }
      }
    }
  }
}
~~~~~~~~~~~
{: #fig-example-C-to-AS-symm title="Example C-to-AS POST /token Request for an Access Token Bound to an Asymmetric Key."}

In the example above, the client specifies that its authentication credential in the OSCORE group is the CCS shown in {{fig-client-auth-cred}}.

~~~~~~~~~~~
{
  / sub / 2 : "42-50-31-FF-EF-37-32-39",
  / cnf / 8 : {
    / COSE_Key / 1 : {
      / kty /  1 : 2 / EC2 /,
      / crv / -1 : 1 / P-256 /,
      / x /   -2 : h'd7cc072de2205bdc1537a543d53c60a6
                     acb62eccd890c7fa27c9e354089bbe13',
      / y /   -3 : h'f95e1d4b851a2cc80fff87d8e23f22af
                     b725d535e515d020731e79a3b4e47120'
    }
  }
}
~~~~~~~~~~~
{: #fig-client-auth-cred title="Example of client Authentication Credential as CWT Claims Set (CCS)."}


\[

TODO: Specify how C requests a new access token that dynamically updates its access rights. (See {{sec-as-update-access-rights}} for pre-requirements and a high-level direction)

\]

### 'context_id' Parameter ### {#context_id}

The 'context_id' parameter is an OPTIONAL parameter of the Access Token Request message defined in {{Section 5.8.1 of RFC9200}}. This parameter provides a value that the client wishes to use with the RS as a hint for a security context. Its exact content is profile specific.

### 'salt_input' Parameter ### {#salt_input}

The 'salt_input' parameter is an OPTIONAL parameter of the Access Token Request message defined in {{Section 5.8.1 of RFC9200}}. This parameter provides a value that the client wishes to use as part of a salt with the RS, for deriving cryptographic keying material. Its exact content is profile specific.

### 'client_cred_verify' Parameter ### {#client_cred_verify}

The 'client_cred_verify' parameter is an OPTIONAL parameter of the Access Token Request message defined in {{Section 5.8.1. of RFC9200}}. This parameter provides a signature computed by the client to prove the possession of its own private key.

### 'client_cred_verify_mac' Parameter ### {#client_cred_verify_mac}

The 'client_cred_verify_mac' parameter is an OPTIONAL parameter of the Access Token Request message defined in {{Section 5.8.1. of RFC9200}}. This parameter provides a Message Authentication Code (MAC) computed by the client to prove the possession of its own private key.

## AS-to-C: Response ## {#sec-as-c-token}

After having verified the POST request to the /token endpoint and that the client is authorized to obtain an access token corresponding to its Access Token Request, the AS MUST verify the proof-of-possession (PoP) evidence. In particular, the AS proceeds as follows.

* As PoP input, the AS uses the same value used by the client in {{sec-c-as-token-endpoint}}.

* As public key of the client, the AS uses the one included in the authentication credential specified in the 'req_cnf' parameter of the Access Token Request.

   This requires the AS to support the format of the authentication credential specified in the 'req_cnf' parameter, i.e., the format of authentication credential that is used in the OSCORE group where the client uses that authentication credential. Practically, this is not an issue, since an RS supporting this profile is expected to be registered only at an AS that supports the formats of authentication credential that the RS supports.

* If the Access Token Request includes the 'client_cred_verify' parameter, this specifies the PoP evidence as a signature. Then, the AS verifies the signature by using the public key of the client.

   This requires the AS to support the signature algorithm and curve (when applicable) that are used in the OSCORE group where the client uses the authentication credential specified in the 'req_cnf' parameter of the Access Token Request. Practically, this is not an issue, since an RS supporting this profile is expected to be registered only at an AS that supports the signature algorithms and curves (when applicable) that the RS supports.

* If the Access Token Request includes the 'client_cred_verify_mac' parameter, this specifies the PoP evidence as a Message Authentication Code (MAC).

   Then, the AS recomputes the MAC through the same process taken by the client when preparing the value of the 'client_cred_verify_mac' parameter for the access token (see {{sec-c-as-token-endpoint}}), with the difference that the AS uses its own Diffie-Hellman private key and the Diffie-Hellman public key of the client. The verification succeeds if and only if the recomputed MAC is equal to the MAC conveyed as PoP evidence in the Access Token Request.

   This requires the AS to support the ECDH algorithm that is used as Pairwise Key Agreement Algorithm in the OSCORE group where the client uses the authentication credential specified in the 'req_cnf' parameter of the Access Token Request. Practically, this is not an issue, since an RS supporting this profile is expected to be registered only at an AS that supports the ECDH algorithms that the RS supports.

If both the 'client_cred_verify' and 'client_cred_verify_mac' parameters are present, or if the verification of the PoP evidence fails, the AS considers the client request invalid.

If the client request was invalid or not authorized, the AS returns an error response as described in {{Section 5.8.3 of RFC9200}}.

If all verifications are successful, the AS responds as defined in {{Section 5.8.2 of RFC9200}}. In particular:

   * The AS can signal that the use of Group OSCORE is REQUIRED for a specific access token by including the 'ace_profile' parameter with the value "coap_group_oscore" in the Access Token Response. The client MUST use Group OSCORE towards all the resource servers for which this access token is valid. Usually, it is assumed that constrained devices will be pre-configured with the necessary profile, so that this kind of profile signaling can be omitted.

   * The AS MUST NOT include the 'rs_cnf' parameter defined in {{RFC9201}}. In general, the AS may not be aware of the authentication credentials (and public keys included thereof) that the RSs use in the OSCORE group. Also, the client is able to retrieve the authentication credentials of other group members from the responsible Group Manager, both upon joining the group or later on as a group member, as defined in {{I-D.ietf-ace-key-groupcomm-oscore}}.

   * According to this document, the AS includes the 'access_token' parameter specifying the issued access token in the Access Token Response. An alternative workflow where the access token is uploaded by the AS directly to the RS is described in {{I-D.ietf-ace-workflow-and-params}}.

The AS MUST include the following information as metadata of the issued access token. The use of CBOR web tokens (CWT) as specified in {{RFC8392}} is RECOMMENDED.

* The profile "coap_group_oscore". If the access token is a CWT, this is specified in the 'ace_profile' claim of the access token, as per {{Section 5.10 of RFC9200}}.

* The salt input specified in the 'salt_input' parameter of the Access Token Request. If the access token is a CWT, the content of the 'salt_input' parameter MUST be specified in the 'salt_input' claim of the access token, defined in {{salt_input_claim}} of this document.

* The Context ID input specified in the 'context_id' parameter of the Access Token Request. If the access token is a CWT, the content of the 'context_id' parameter MUST be specified in the 'context_id' claim of the access token, defined in {{context_id_claim}} of this document.

* The authentication credential that the client uses in the OSCORE group and specified in the 'req_cnf' parameter of the Access Token Request.

   If the access token is a CWT, the client's authentication credential MUST be specified in the 'cnf' claim, which follows the syntax from {{Section 3.1 of RFC8747}}. In particular, the 'cnf' claim includes the same authentication credential specified in the 'req_cnf' parameter of the Access Token Request (see {{sec-c-as-token-endpoint}}).

{{fig-example-AS-to-C}} shows an example of such an AS response. The access token has been truncated for readability.

~~~~~~~~~~~
Header: Created (Code=2.01)
Content-Format: 19 (application/ace+cbor)
Payload:
{
  / access_token / 1 : h'8343a1010aa2044c...00', / elided for brevity /
  / ace_profile / 38 : e'coap_group_oscore',
  / expires_in /   2 : 3600
}
~~~~~~~~~~~
{: #fig-example-AS-to-C title="Example AS-to-C Access Token Response with the Group OSCORE Profile."}

{{fig-example-AS-to-C-CWT}} shows an example CWT Claims Set, containing the client's public key in the group (as pop-key), as specified by the inner confirmation value in the 'cnf' claim.

~~~~~~~~~~~
{
  / aud /           3 : "tempSensorInLivingRoom",
  / iat /           6 : 1719820800,
  / exp /           4 : 2035353600,
  / scope /         9 : "temperature_g firmware_p",
  e'context_id_claim' : h'abcd0000',
  e'salt_input_claim' : h'00',
  / cnf /           8 : {
    e'kccs' : {
      / sub / 2 : "42-50-31-FF-EF-37-32-39",
      / cnf / 8 : {
        / COSE_Key / 1 : {
          / kty /  1 : 2 / EC2 /,
          / crv / -1 : 1 / P-256 /,
          / x /   -2 : h'd7cc072de2205bdc1537a543d53c60a6
                         acb62eccd890c7fa27c9e354089bbe13',
          / y /   -3 : h'f95e1d4b851a2cc80fff87d8e23f22af
                         b725d535e515d020731e79a3b4e47120'
        }
      }
    }
  }
}
~~~~~~~~~~~
{: #fig-example-AS-to-C-CWT title="Example CWT Claims Set."}

The same CWT Claims Set as in {{fig-example-AS-to-C-CWT}} and encoded in CBOR is shown in {{fig-example-AS-to-C-CWT-encoding}}, using the value abbreviations defined in {{RFC9200}} and {{RFC8747}}. The bytes in hexadecimal are reported in the first column, while their corresponding CBOR meaning is reported after the "#" sign on the second column, for easiness of readability.

Editor's note: it should be checked (and in case fixed) that the values used below (which are not yet registered) are the final values registered by IANA.

~~~~~~~~~~~
A7                                      # map(7)
   03                                   # unsigned(3)
   76                                   # text(22)
      74656D7053656E736F72496E4C6976696E67526F6F6D
      # "tempSensorInLivingRoom"
   06                                   # unsigned(6)
   1A 66826200                          # unsigned(1719820800)
   04                                   # unsigned(4)
   1A 79510800                          # unsigned(2035353600)
   09                                   # unsigned(9)
   78 18                                # text(24)
      74656D70657261747572655F67206669726D776172655F70
      # "temperature_g firmware_p"
   18 33                                # unsigned(51)
   44                                   # bytes(4)
      ABCD0000
   18 34                                # unsigned(52)
   41                                   # bytes(1)
      00
   08                                   # unsigned(8)
   A1                                   # map(1)
      0E                                # unsigned(14)
      A2                                # map(2)
         02                             # unsigned(2)
         77                             # text(23)
            34322D35302D33312D46462D45462D33372D33322D3339
            # "42-50-31-FF-EF-37-32-39"
         08                             # unsigned(8)
         A1                             # map(1)
            01                          # unsigned(1)
            A4                          # map(4)
               01                       # unsigned(1)
               02                       # unsigned(2)
               20                       # negative(0)
               01                       # unsigned(1)
               21                       # negative(1)
               58 20                    # bytes(32)
                  D7CC072DE2205BDC1537A543D53C60A6
                  ACB62ECCD890C7FA27C9E354089BBE13
               22                       # negative(2)
               58 20                    # bytes(32)
                  F95E1D4B851A2CC80FFF87D8E23F22AF
                  B725D535E515D020731E79A3B4E47120
~~~~~~~~~~~
{: #fig-example-AS-to-C-CWT-encoding title="Example CWT Claims Set Using CBOR Encoding."}


### Update of Access Rights # {#sec-as-update-access-rights}

\[

TODO: Specify how the AS issues an access token that dynamically updates the access rights of C. (See below for pre-requirements and a high-level direction)

(This should be specified with content in the present section, as well as in {{sec-c-as-token-endpoint}} and {{sec-rs-update-access-rights}}).

At the moment, this profile does not support the dynamic update of access rights for the client like other transport profiles of ACE do.

This can be enabled by building on concepts defined in {{I-D.ietf-ace-workflow-and-params}}:

* "Token series" - In this profile, it would be specialized as a set of consecutive access tokens issued by the AS for the pair (C, AUD), where C is the client whose public authentication credential is bound to those access tokens, while AUD is the audience for which C requests those access tokens.

* "token_series_id" - At the time of writing, {{I-D.ietf-ace-workflow-and-params}} describes the intended direction for defining this new prospective parameter, to be used in the Access Token Request/Response exchange between C and the AS.

  This parameter is meant to specify the unique identifier of a token series. In parallel, it is planned to define a new, corresponding claim to include into access tokens.

At a high-level, the above can enable the dynamic update of access rights as follows:

* Each access token in a token series includes the claim "token_series_id", with value the identifier of the token series that the access token belongs to.

* When issuing the first access token in a token series, the AS includes the parameter "token_series_id" in the Access Token Response to the client, with value the identifier of the token series that the access token belongs to.

* When C requests from the AS an access token that dynamically updates its current access rights to access protected resources at the same audience, C sends to the AS an Access Token Request such that:

  - It includes the parameter "token_series_id", with value the identifier of the token series for which the new access token is requested.

  - It does _not_ include the parameters "context_id", "salt_input", and "client_cred_verify" or "client_cred_verify_mac".

* If the AS issues the new access token that dynamically updated the access rights of C, then the access token includes the claim "token_series_id", with value the identifier of the same token series for which the access token has been issued.

When receiving the new access token, the RS uses the value of the claim "token_series_id", and identifies the stored old access token that has to be superseded by the new one, as both belonging to the same token series.

\]

### 'context_id' Claim ### {#context_id_claim}

The 'context_id' claim provides a value that the client requesting the access token wishes to use with the RS, as a hint for a security context.

This parameter specifies the value of the Context ID input, encoded as a CBOR byte string.

### 'salt_input' Claim ### {#salt_input_claim}

The 'salt_input' claim provides a value that the client requesting the access token wishes to use as a part of a salt with the RS, e.g., for deriving cryptographic material.

This parameter specifies the value of the salt input, encoded as a CBOR byte string.

# Client-RS Communication # {#sec-c-rs-comm}

This section details the POST request and response to the /authz-info endpoint between the client and the RS.

The proof-of-possession required to bind the access token to the client is explicitly performed when the RS receives and verifies a request from the client protected with Group OSCORE, either with the group mode (see {{Section 7 of I-D.ietf-core-oscore-groupcomm}}) or with the pairwise mode (see {{Section 8 of I-D.ietf-core-oscore-groupcomm}}).

In particular, the RS uses the client's public key bound to the access token, either when verifying the signature of the request (if protected with the group mode), or when verifying the request as integrity-protected with pairwise keying material derived from the two peers' authentication credentials and asymmetric keys (if protected with the pairwise mode). In either case, the RS also authenticates the client.

Similarly, when receiving a protected response from the RS, the client uses the RS's public key either when verifying the signature of the response (if protected with the group mode), or when verifying the response as integrity-protected with pairwise keying material derived from the two peers' authentication credentials and asymmetric keys (if protected with the pairwise mode). In either case, the client also authenticates the RS. Mutual authentication is only achieved after the client has successfully verified the protected response from the RS.

Therefore, an attacker using a stolen access token cannot generate a valid Group OSCORE message as protected through the client's private key, and thus cannot prove possession of the pop-key bound to the access token. Also, if a client legitimately owns an access token but has not joined the OSCORE group, it cannot generate a valid Group OSCORE message, as it does not store the necessary keying material shared among the group members.

Furthermore, a client C1 is supposed to obtain a valid access token from the AS, as specifying its own authentication credential (and the public key included thereof) associated with its own private key used in the OSCORE group, together with its own Sender ID in that OSCORE group (see {{sec-c-as-token-endpoint}}). This allows the RS receiving the access token to verify with the Group Manager of that OSCORE group whether such a client indeed has that Sender ID and uses that authentication credential in the OSCORE group.

As a consequence, a different client C2, also member of the same OSCORE group, is not able to impersonate C1, by: i) getting a valid access token, specifying the Sender ID of C1 and a different (made-up) authentication credential; ii) successfully posting the access token to the RS; and then iii) attempting to communicate using Group OSCORE and impersonating C1, while also blaming C1 for the consequences of the interactation with the RS.

## C-to-RS POST to /authz-info Endpoint ## {#sec-c-rs-authz}

The client uploads the access token to the /authz-info endpoint of the RS, as defined in {{Section 5.10.1 of RFC9200}}.

## RS-to-C: 2.01 (Created) ## {#sec-rs-c-created}

The RS MUST verify the validity of the access token as defined in {{Section 5.10.1 of RFC9200}}, with the following additions.

* The RS MUST check that the claims 'salt_input', 'context_id', and 'cnf' are included in the access token.

* The RS considers: the content of the 'context_id' claim as the GID of the OSCORE group; the content of the 'salt_input' claim as the Sender ID that the client has in the group; and the inner confirmation value of the 'cnf' claim as the authentication credential that the client uses in the group.

   The RS MUST check whether it already stores the authentication credential specified in the inner confirmation value of the 'cnf' claim as associated with the pair (GID, Sender ID) above.

   If this is not the case, the RS MUST request the client's authentication credential to the Group Manager of the OSCORE group as described in {{Section 9.3 of I-D.ietf-ace-key-groupcomm-oscore}}, specifying the client's Sender ID in the OSCORE group, i.e., the value of the 'salt_input' claim. Then, the RS performs the following actions.

     - The RS MUST check whether the client's authentication credential retrieved from the Group Manager matches the one retrieved from the inner confirmation value of the 'cnf' claim of the access token.

     - The RS MUST check whether the client's Sender ID provided by the Group Manager together with the client's authentication credential matches the one retrieved from the 'salt_input' claim of the access token.

If any of the checks above fails, the RS MUST consider the access token invalid, and MUST reply to the client with an error response code equivalent to the CoAP code 4.00 (Bad Request).

If the access token is valid and further checks on its content are successful, the RS associates the authorization information from the access token with the Group OSCORE Security Context.

In particular, the RS associates the authorization information from the access token with the triple (GID, SaltInput, AuthCred), where GID is the Group Identifier of the OSCORE group, while SaltInput and AuthCred are the Sender ID and the authentication credential that the client uses in that OSCORE group, respectively.

The RS MUST keep this association up-to-date over time, as the triple (GID, SaltInput, AuthCred) associated with the access token might change. In particular:

* If the OSCORE group is rekeyed (see {{Section 12.2 of I-D.ietf-core-oscore-groupcomm}} and {{Section 11 of I-D.ietf-ace-key-groupcomm-oscore}}), the Group Identifier also changes in the group, and the new one replaces the current 'GID' value in the triple (GID, SaltInput, AuthCred).

* If the client requests and obtains a new OSCORE Sender ID from the Group Manager (see {{Section 2.6.3.1 of I-D.ietf-core-oscore-groupcomm}} and {{Section 9.2 of I-D.ietf-ace-key-groupcomm-oscore}}), the new Sender ID replaces the current 'SaltInput' value in the triple (GID, SaltInput, AuthCred).

As defined in {{sec-client-public-key-change}}, a possible change of the client's authentication credential requires the client to upload to the RS a new access token bound to the new authentication credential.

Finally, the RS MUST send a 2.01 (Created) response to the client, as defined in {{Section 5.10.1 of RFC9200}}.

## Client-RS Secure Communication ## {#sec-client-rs-secure-communication}

When previously joining the OSCORE group, both the client and the RS have already established the related Group OSCORE Security Context to communicate as group members. Therefore, they can simply start to securely communicate using Group OSCORE, without deriving any additional keying material or security association.

If either of the client or the RS deletes an access token (e.g., when the access token has expired or has been revoked), it MUST NOT delete the related Group OSCORE Security Context.

### Client Side

After having received the 2.01 (Created) response from the RS, following the POST request to the /authz-info endpoint, the client starts the communication with the RS, by sending a request protected with Group OSCORE using the Group OSCORE Security Context {{I-D.ietf-core-oscore-groupcomm}}.

When communicating with the RS to access the resources as specified by the authorization information, the client MUST use the Group OSCORE Security Context of the pertinent OSCORE group, whose GID was specified in the 'context_id' parameter of the Access Token Request.

### Resource Server Side

After successful validation of the access token as defined in {{sec-rs-c-created}} and after having sent the 2.01 (Created) response, the RS can start to communicate with the client using Group OSCORE {{I-D.ietf-core-oscore-groupcomm}}.

When processing an incoming request protected with Group OSCORE, the RS MUST consider as valid client's authentication credential only the one associated with the stored access token. As defined in {{sec-client-public-key-change}}, a possible change of the client's authentication credential requires the client to upload to the RS a new access token bound to the new authentication credential.

For every incoming request, if Group OSCORE verification succeeds, the verification of access rights is performed as described in {{sec-c-rs-access-rights}}.

If the RS receives a request protected with a Group OSCORE Security Context CTX, the target resource requires authorization, and the RS does not store a valid access token related to CTX, then the RS MUST reply with a 4.01 (Unauthorized) error response protected with CTX.

## Update of Access Rights # {#sec-rs-update-access-rights}

\[

TODO: Specify the processing on the RS when receiving an access token that dynamically updates the access rights of C. (See {{sec-as-update-access-rights}} for pre-requirements and a high-level direction)

\]

## Access Rights Verification ## {#sec-c-rs-access-rights}

The RS MUST follow the procedures defined in {{Section 5.10.2 of RFC9200}}. If an RS receives a request protected with Group OSCORE from a client, the RS processes the request according to {{I-D.ietf-core-oscore-groupcomm}}.

If the Group OSCORE verification succeeds and the target resource requires authorization, the RS retrieves the authorization information from the access token associated with the Group OSCORE Security Context. Then, the RS MUST verify that the action requested on the resource is authorized.

If the RS has no valid access token for the client, the RS MUST reject the request and MUST reply to the client with a 4.01 (Unauthorized) error response.

If the RS has an access token for the client but no actions are authorized on the target resource, the RS MUST reject the request and MUST reply to the client with a 4.03 (Forbidden) error response.

If the RS has an access token for the client but the requested action is not authorized, the RS MUST reject the request and MUST reply to the client with a 4.05 (Method Not Allowed) error response.

## Storing Multiple Access Tokens per PoP-Key

According to {{Section 5.10.1 of RFC9200}}, an RS is recommended to store only one access token per proof-of-possession key (pop-key), and to supersede such an access token when receiving and successfully validating a new one bound to the same pop-key.

However, when using the profile specified in this document, an RS might practically have to deviate from that recommendation and store multiple access tokens bound to the same pop-key, i.e., to the same public authentication credential of a client.

For example, this can occur in the following cases.

* The RS is the single RS associated with an audience AUD1, and also belongs to a group-audience AUD2 (see {{Section 6.9 of RFC9200}}).

  A client C with public authentication credential AUTH_CRED_C can request two access tokens T1 and T2 from the AS, such that:

  - T1 targets AUD1 and has scope SCOPE1;

  - T2 targets AUD2 and has scope SCOPE2 different from SCOPE1.

  Both T1 and T2 are going to be bound to the same pop-key specified by AUTH_CRED_C.

  In fact, if the AS issues access tokens targeting a group-audience, then the above can possibly be the case when using any transport profile of ACE that supports asymmetric pop-keys. If so, the RS should be ready to store at minimum one access token per pop-key per audience it belongs to.

* The RS is a member of two OSCORE groups G1 and G2. In particular, the same format of public authentication credentials is used in both OSCORE groups.

  A client C with public authentication credential AUTH_CRED_C of such format, also member of the two OSCORE group G1 and G2, can conveniently use AUTH_CRED_C as its public authentication credential in both those groups. Therefore, C can request two access tokens T1 and T2 from the AS, such that:

  - T1 targets RS and reflects the membership of C in G1, as per its claims "context_id" and "salt_input";

  - T2 targets RS and reflects the membership of C in G2, as per its claims "context_id" and "salt_input".

  Both T1 and T2 are going to be bound to the same pop-key specified by AUTH_CRED_C.

  When using the profile specified in this document, the RS should be ready to store at minimum one access token per pop-key per OSCORE group it is a member of (although, per the previous point, even this can be limiting).

* The RS uses both the profile specified in this document and a different transport profile of ACE that also relies on asymmetric pop-keys, e.g., the EDHOC and OSCORE profile defined in {{I-D.ietf-ace-edhoc-oscore-profile}}.

  In such a case, a client C with public authentication credential AUTH_CRED_C can request two access tokens T1 and T2 from the AS, such that:

  - T1 targets RS and is meant to be used according to the Group OSCORE profile defined in this document;

  - T2 targets RS and is meant to be used according to the EDHOC and OSCORE profile defined in {{I-D.ietf-ace-edhoc-oscore-profile}}.

  Both T1 and T2 are going to be bound to the same pop-key specified by AUTH_CRED_C.

  When using multiple transport profiles of ACE that rely on asymmetric pop-keys, it is reasonable that the RS is capable to store at minimum one access token per pop-key per used profile (although, per the previous points, even this can be limiting).

# Change of Client's Authentication Credential in the Group ## {#sec-client-public-key-change}

During its membership in the OSCORE group, the client might change the authentication credential that it uses in the group. When this happens, the client uploads the new authentication credential to the Group Manager, as defined in {{Section 9.4 of I-D.ietf-ace-key-groupcomm-oscore}}.

After that, and in order to continue communicating with the RS, the client MUST perform the following actions.

1. The client requests a new access token to the AS, as defined in {{sec-c-as-comm}}. In particular, when sending the Access Token Request as defined in {{sec-c-as-token-endpoint}}, the client specifies:

   * The current Group Identifier of the OSCORE group, as value of the 'context_id' parameter.

   * The current Sender ID that it has in the OSCORE group, as value of the 'salt_input' parameter.

   * The new authentication credential that it uses in the OSCORE group, as inner confirmation value of the 'req_cnf' parameter.

   * The proof-of-possession (PoP) evidence corresponding to the public key of the new authentication credential, as value of the 'client_cred_verify' or 'client_cred_verify_mac' parameter.

2. After receiving the Access Token Response from the AS (see {{sec-as-c-token}}), the client performs the same exchanges with the RS as defined in {{sec-c-rs-comm}}.

When receiving the new access token, the RS performs the same steps defined in {{sec-rs-c-created}}, with the following addition in case the new access token is successfully verified and stored:

* The RS also deletes the old access token, i.e., the one whose associated triple (GID, SaltInput, AuthCred) has the same GID and SaltInput values as in the triple that is associated with the new access token and that includes the new authentication credential of the client.

# Secure Communication with the AS # {#sec-comm-as}

As specified in the ACE framework (see {{Sections 5.8 and 5.9 of RFC9200}}), the requesting entity (client and/or RS) and the AS communicate via the /token or /introspect endpoint. The use of CoAP and OSCORE {{RFC8613}} for this communication is RECOMMENDED in this profile. Other protocols fulfilling the security requirements defined in {{Sections 5 and 6 of RFC9200}} (such as HTTP and DTLS or TLS) MAY be used instead.

If OSCORE {{RFC8613}} is used, the requesting entity and the AS are expected to have a pre-established Security Context in place. How this Security Context is established is out of the scope of this profile. Furthermore, the requesting entity and the AS communicate using OSCORE through the /token endpoint as specified in {{Section 5.8 of RFC9200}}, and through the /introspect endpoint as specified in {{Section 5.9 of RFC9200}}.

# Discarding the Security Context # {#sec-discard-context}

As members of an OSCORE group, the client and the RS may independently leave the group or be forced to, e.g., if compromised or suspected so. Upon leaving the OSCORE group, the client or RS also discards the Group OSCORE Security Context, which may anyway be renewed by the Group Manager through a group rekeying process (see {{Section 12.2 of I-D.ietf-core-oscore-groupcomm}}).

The client or RS can acquire a new Group OSCORE Security Context, by re-joining the OSCORE group, e.g., by using the approach defined in {{I-D.ietf-ace-key-groupcomm-oscore}}. In such a case, the client SHOULD request a new access token to be uploaded to the RS.

# CBOR Mappings # {#sec-cbor-mappings}

The new parameters defined in this document MUST be mapped to CBOR types as specified in {{table-cbor-mappings-parameters}}, using the given integer abbreviation for the map key.

| Parameter name         | CBOR Key | Value Type  |
| context_id             | TBD      | byte string |
| salt_input             | TBD      | byte string |
| client_cred_verify     | TBD      | byte string |
| client_cred_verify_mac | TBD      | byte string |
{: #table-cbor-mappings-parameters title="CBOR Mappings for New Parameters." align="center"}

The new claims defined in this document MUST be mapped to CBOR types as specified in {{table-cbor-mappings-claims}}, using the given integer abbreviation for the map key.

| Claim name | CBOR Key | Value Type  |
| context_id | TBD      | byte string |
| salt_input | TBD      | byte string |
{: #table-cbor-mappings-claims title="CBOR Mappings for New Claims." align="center"}

# Security Considerations # {#sec-security-considerations}

This document specifies a profile for the Authentication and Authorization for Constrained Environments (ACE) framework {{RFC9200}}. Thus, the general security considerations from the ACE framework also apply to this profile.

The proof-of-possession (PoP) key bound to an access token is always an asymmetric key, i.e., the public key included in the authentication credential that the client uses in the OSCORE group. This means that there is never a same shared secret used as PoP key with possible multiple RSs. Therefore, it is possible and safe for the AS to issue an access token for an audience that includes multiple RSs (i.e., a group-audience, see {{Section 6.9 of RFC9200}}).

In such a case, as per {{Section 6.1 of RFC9200}}, the AS has to ensure the integrity protection of the access token by protecting it through an asymmetric signature. In addition, the used group-audience has to correctly identify all the RSs that are intended recipients of the access token, and for which the single scope specified in the access token applies. As a particular case, the audience can be the name of the OSCORE group, if the access token is intended for all the RSs in that group.

Furthermore, this document inherits the general security considerations about Group OSCORE {{I-D.ietf-core-oscore-groupcomm}}, as to the specific use of Group OSCORE according to this profile.

Group OSCORE is designed to secure point-to-point as well as point-to-multipoint communications, providing a secure binding between a single request and multiple corresponding responses. In particular, Group OSCORE fulfills the same security requirements of OSCORE.

Group OSCORE ensures source authentication of messages both in group mode (see {{Section 7 of I-D.ietf-core-oscore-groupcomm}}) and in pairwise mode (see {{Section 8 of I-D.ietf-core-oscore-groupcomm}}).

When protecting an outgoing message in group mode, the sender uses its private key to compute a digital signature, which is embedded in the protected message. The group mode can be used to protect messages sent to multiple recipients (e.g., over IP multicast) or to a single recipient.

When protecting an outgoing message in pairwise mode, the sender uses a pairwise symmetric key, which is derived from the asymmetric keys of the two peers exchanging the message. The pairwise mode can be used to protect only messages intended for a single recipient.

# Privacy Considerations # {#sec-privacy-considerations}

This document specifies a profile for the Authentication and Authorization for Constrained Environments (ACE) framework {{RFC9200}}. Thus the general privacy considerations from the ACE framework also apply to this profile.

As this profile uses Group OSCORE, the privacy considerations from {{I-D.ietf-core-oscore-groupcomm}} apply to this document as well.

An unprotected response to an unauthorized request may disclose information about the RS and/or its existing relationship with the client. It is advisable to include as little information as possible in an unencrypted response. However, since both the client and the RS share a Group OSCORE Security Context, unauthorized, yet protected requests are followed by protected responses, which can thus include more detailed information.

Although it may be encrypted, the access token is sent in the clear to the /authz-info endpoint at the RS. Thus, if the client uses the same single access token from multiple locations with multiple resource servers, it can risk being tracked through the access token's value.

Note that, even though communications are protected with Group OSCORE, some information might still leak, due to the observable size, source address, and destination address of exchanged messages.

# IANA Considerations # {#iana}

This document has the following actions for IANA.

Note to RFC Editor: Please replace "{{&SELF}}" with the RFC number of this document and delete this paragraph.

## ACE Profiles Registry ## {#iana-ace-oauth-profile}

IANA is asked to add the following entry to the "ACE Profiles" registry within the "Authentication and Authorization for Constrained Environments (ACE)" registry group, following the procedure specified in {{Section 8.8 of RFC9200}}.

* Name: coap_group_oscore
* Description: Profile to secure communications between constrained nodes using the Authentication and Authorization for Constrained Environments framework, by enabling authentication and fine-grained authorization of members of an OSCORE group that use a pre-established Group OSCORE Security Context to communicate with Group OSCORE.
* CBOR Value: TBD (value between 1 and 255)
* Reference: {{&SELF}}

## OAuth Parameters Registry ## {#iana-oauth-params}

IANA is asked to add the following entries to the "OAuth Parameters" registry, following the procedure specified in {{Section 11.2 of RFC6749}}.

* Name: context_id
* Parameter Usage Location: token request
* Change Controller: IETF
* Reference: {{context_id}} of {{&SELF}}

<br>

* Name: salt_input
* Parameter Usage Location: token request
* Change Controller: IETF
* Reference: {{salt_input}} of {{&SELF}}

<br>

* Name: client_cred_verify
* Parameter Usage Location: token request
* Change Controller: IETF
* Reference: {{client_cred_verify}} of {{&SELF}}

<br>

* Name: client_cred_verify_mac
* Parameter Usage Location: token request
* Change Controller: IETF
* Reference: {{client_cred_verify_mac}} of {{&SELF}}

## OAuth Parameters CBOR Mappings Registry ## {#iana-token-cbor-mappings}

IANA is asked to add the following entries to the "OAuth Parameters CBOR Mappings" registry within the "Authentication and Authorization for Constrained Environments (ACE)" registry group, following the procedure specified in {{Section 8.10 of RFC9200}}.

* Name: context_id
* CBOR Key: TBD
* Value Type: byte string
* Reference: {{context_id}} of {{&SELF}}
* Original Specification: {{&SELF}}

<br>

* Name: salt_input
* CBOR Key: TBD
* Value Type: byte string
* Reference: {{salt_input}} of {{&SELF}}
* Original Specification: {{&SELF}}

<br>

* Name: client_cred_verify
* CBOR Key: TBD
* Value Type: byte string
* Reference: {{client_cred_verify}} of {{&SELF}}
* Original Specification: {{&SELF}}

<br>

* Name: client_cred_verify_mac
* CBOR Key: TBD
* Value Type: byte string
* Reference: {{client_cred_verify_mac}} of {{&SELF}}
* Original Specification: {{&SELF}}

## CBOR Web Token (CWT) Claims Registry ## {#iana-token-cwt-claims}

IANA is asked to add the following entries to the "CBOR Web Token (CWT) Claims" registry, following the procedure specified in {{Section 9.1 of RFC8392}}.

* Claim Name: context_id
* Claim Description: Client provided Context ID
* JWT Claim Name: N/A
* Claim Key: TBD
* Claim Value Type: byte string
* Change Controller: IETF
* Reference: {{context_id_claim}} of {{&SELF}}

<br>

* Claim Name: salt_input
* Claim Description: Client provided salt input
* JWT Claim Name: N/A
* Claim Key: TBD
* Claim Value Type: byte string
* Change Controller: IETF
* Reference: {{salt_input_claim}} of {{&SELF}}

## TLS Exporter Label Registry ## {#iana-tls-exporter-label}

IANA is asked to add the following entry to the "TLS Exporter Label" registry within the "Transport Layer Security (TLS) Parameters" registry group, following the procedure specified in {{Section 6 of RFC5705}} and updated in {{Section 12 of RFC8447}}.

* Value: EXPORTER-ACE-PoP-Input-Client-AS
* DTLS-OK: Y
* Recommended: N
* Reference: {{sec-c-as-token-endpoint}} of {{&SELF}}

--- back

# Profile Requirements # {#profile-requirements}

This appendix lists the specifications of this profile based on the requirements of the ACE framework, as requested in {{Section C of RFC9200}}.

* Optionally, define new methods for the client to discover the necessary permissions and AS for accessing a resource, different from the one proposed in {{RFC9200}}: Not specified.

* Optionally, specify new grant types: Not specified.

* Optionally, define the use of client certificates as client credential type: Not specified.

* Specify the communication protocol the client and RS must use: CoAP.

* Specify the security protocol the client and RS must use to protect their communication: Group OSCORE, by using a pre-established Group OSCORE Security Context.

* Specify how the client and the RS mutually authenticate: Explicitly, by possession of a common Group OSCORE Security Context, and by either: usage of digital signatures embedded in messages, if protected with the group mode of Group OSCORE; or protection of messages with the pairwise mode of Group OSCORE, by using pairwise symmetric keys derived from the asymmetric keys of the two peers exchanging the message. Note that mutual authentication is not completed before the client has verified a Group OSCORE response using the corresponding Group OSCORE Security Context.

* Specify the proof-of-possession protocol(s) and how to select one, if several are available. Also specify which key types (e.g., symmetric/asymmetric) are supported by a specific proof-of- possession protocol: Group OSCORE algorithms; asymmetric keys verified and distributed by a Group Manager.

* Specify a unique ace_profile identifier: coap_group_oscore.

* If introspection is supported, specify the communication and security protocol for introspection: HTTP/CoAP (+ TLS/DTLS/OSCORE).

* Specify the communication and security protocol for interactions between the client and AS: HTTP/CoAP (+ TLS/DTLS/OSCORE).

* Specify if/how the /authz-info endpoint is protected, including how error responses are protected: Not protected.

* Optionally, define other methods of token transport than the /authz-info endpoint: Not defined.

# CDDL Model # {#sec-cddl-model}
{:removeinrfc}

~~~~~~~~~~~~~~~~~~~~ CDDL
; ACE Profiles
coap_group_oscore = 5

; OAuth Parameters CBOR Mappings
context_id_param = 71
salt_input_param = 72
client_cred_verify = 73
client_cred_verify_mac = 74

; CBOR Web Token (CWT) Claims
context_id_claim = 51
salt_input_claim = 52

; CWT Confirmation Methods
kccs = 14
~~~~~~~~~~~~~~~~~~~~
{: #fig-cddl-model title="CDDL model" artwork-align="left"}

# Document Updates # {#sec-document-updates}
{:removeinrfc}

## Version -02 to -03 ## {#sec-02-03}

* Lowercase "client", "resource server", "authorization server", and "access token".

* Consistent update of section numbers for external references.

* Mentioned that this profile can also use the ACE alternative workflow.

* Fixes in the IANA considerations.

* Editorial fixes and improvements.

## Version -01 to -02 ## {#sec-01-02}

* CBOR diagnostic notation uses placeholders from a CDDL model.

* Renamed the claim 'contextId_input' to 'context_id'.

* Revised examples.

* Placeholders and early direction for dynamic update of access rights.

* Added text on storing multiple access tokens per PoP-Key on the RS.

* Fixes in the IANA considerations.

* Editorial fixes and improvements.

## Version -00 to -01 ## {#sec-00-01}

* Deleting an access token does not delete the Group OSCORE Security Context.

* Distinct computation of the PoP input when C and the AS use (D)TLS 1.2 or 1.3.

* Revised computation of the PoP input when C and the AS use OSCORE.

* Revised computation of the PoP evidence when the OSCORE group is a pairwise-only group.

* Clarified requirements on the AS for verifying the PoP evidence.

* Renamed the TLS Exporter Label for computing the PoP input.

* Editorial fixes and improvements.

# Acknowledgments # {#acknowldegment}
{:numbered="false"}

{{{Ludwig Seitz}}} contributed as a co-author of initial versions of this document.

The authors sincerely thank {{{Christian Amsüss}}}, {{{Tim Hollebeek}}}, {{{Benjamin Kaduk}}}, {{{John Preuß Mattsson}}}, {{{Dave Robin}}}, {{{Jim Schaad}}}, and {{{Göran Selander}}} for their comments and feedback.

The work on this document has been partly supported by the Sweden's Innovation Agency VINNOVA and the Celtic-Next projects CRITISEC and CYPRESS; and by the H2020 project SIFIS-Home (Grant agreement 952652).
