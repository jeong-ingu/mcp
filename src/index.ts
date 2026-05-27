#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import axios from "axios";
import crypto from "crypto";
import https from "https";

// NCP API 인증 헬퍼
function generateSignature(
  method: string,
  url: string,
  timestamp: string,
  accessKey: string,
  secretKey: string
): string {
  const space = " ";
  const newLine = "\n";
  const hmac = crypto.createHmac("sha256", secretKey);

  hmac.update(method);
  hmac.update(space);
  hmac.update(url);
  hmac.update(newLine);
  hmac.update(timestamp);
  hmac.update(newLine);
  hmac.update(accessKey);

  return hmac.digest("base64");
}

// NCP API 클라이언트
class NCPClient {
  private accessKey: string;
  private secretKey: string;
  private apiUrl: string;

  constructor(accessKey: string, secretKey: string) {
    this.accessKey = accessKey;
    this.secretKey = secretKey;
    this.apiUrl = "https://ncloud.apigw.ntruss.com";
  }

  private async request(method: string, apiPath: string, endpoint: string, params?: any) {
    const timestamp = Date.now().toString();

    let url = `${apiPath}${endpoint}`;
    if (method === "GET" && params && Object.keys(params).length > 0) {
      const queryString = new URLSearchParams(params).toString();
      url = `${url}?${queryString}`;
    }

    const signature = generateSignature(
      method,
      url,
      timestamp,
      this.accessKey,
      this.secretKey
    );

    const config: any = {
      method,
      url: `${this.apiUrl}${url}`,
      headers: {
        "x-ncp-apigw-timestamp": timestamp,
        "x-ncp-iam-access-key": this.accessKey,
        "x-ncp-apigw-signature-v2": signature,
      },
      httpsAgent: new https.Agent({
        rejectUnauthorized: false,
      }),
    };

    if (method === "POST") {
      config.headers["Content-Type"] = "application/x-www-form-urlencoded";
      config.data = new URLSearchParams(params).toString();
    }

    try {
      const response = await axios(config);
      return response.data;
    } catch (error: any) {
      throw new Error(`NCP API Error: ${error.response?.data?.message || error.message}`);
    }
  }

  // ===== Server Instance APIs =====

  async listServers(params?: {
    regionCode?: string;
    vpcNo?: string;
    serverName?: string;
    serverInstanceStatusCode?: string; // INIT | CREAT | RUN | NSTOP
    pageNo?: string;
    pageSize?: string;
    sortedBy?: string;       // serverName | serverInstanceNo
    sortingOrder?: string;   // ASC | DESC
  }) {
    return await this.request("GET", "/vserver/v2", "/getServerInstanceList", params || {});
  }

  async getServerDetail(serverInstanceNo: string) {
    return await this.request("GET", "/vserver/v2", "/getServerInstanceDetail", {
      serverInstanceNo,
    });
  }

  async createServer(params: {
    // 이미지 지정 (세 가지 중 하나 필수)
    serverImageNo?: string;          // KVM/XEN/RHV 신규 이미지
    serverImageProductCode?: string; // RHV/XEN 신규 이미지 (구버전 방식)
    memberServerImageInstanceNo?: string; // 내 커스텀 이미지
    // 스펙
    serverSpecCode?: string;         // serverImageNo 사용 시 스펙 코드
    serverProductCode?: string;      // serverImageProductCode 사용 시 스펙 코드
    // 네트워크 (필수)
    vpcNo: string;
    subnetNo: string;
    // 네트워크 인터페이스 (NIC 0번 필수)
    "networkInterfaceList.1.networkInterfaceOrder": string; // "0"
    "networkInterfaceList.1.accessControlGroupNoList.1": string; // ACG 번호
    // 서버 이름 / 수량
    serverName?: string;
    serverCreateCount?: string;      // 1~100, 기본값 1
    serverCreateStartNo?: string;    // 0~999, 기본값 1
    serverDescription?: string;
    // 인증 / 스크립트
    loginKeyName?: string;
    initScriptNo?: string;
    // 요금 / 보호
    feeSystemTypeCode?: string;      // MTRAT(시간, 기본) | FXSUM(월정액)
    isProtectServerTermination?: string; // true | false
    associateWithPublicIp?: string;  // true | false (Public Subnet + 1대 생성 시만)
    placementGroupNo?: string;
    isEncryptedBaseBlockStorageVolume?: string; // true | false (RHV만)
    isPreInstallGpuDriver?: string;  // true | false
    regionCode?: string;
  }) {
    return await this.request("POST", "/vserver/v2", "/createServerInstances", params);
  }

  async startServer(serverInstanceNo: string) {
    return await this.request("GET", "/vserver/v2", "/startServerInstances", {
      "serverInstanceNoList.1": serverInstanceNo,
    });
  }

  async stopServer(serverInstanceNo: string) {
    return await this.request("GET", "/vserver/v2", "/stopServerInstances", {
      "serverInstanceNoList.1": serverInstanceNo,
    });
  }

  async rebootServer(serverInstanceNo: string) {
    return await this.request("GET", "/vserver/v2", "/rebootServerInstances", {
      "serverInstanceNoList.1": serverInstanceNo,
    });
  }

  async deleteServer(serverInstanceNo: string) {
    return await this.request("GET", "/vserver/v2", "/terminateServerInstances", {
      "serverInstanceNoList.1": serverInstanceNo,
    });
  }

  async changeServerSpec(serverInstanceNo: string, serverSpecCode: string) {
    return await this.request("GET", "/vserver/v2", "/changeServerInstanceSpec", {
      serverInstanceNo,
      serverSpecCode,
    });
  }

  async setProtectServerTermination(serverInstanceNo: string, isProtect: boolean) {
    return await this.request("GET", "/vserver/v2", "/setProtectServerTermination", {
      serverInstanceNo,
      isProtectServerTermination: String(isProtect),
    });
  }

  async getRootPassword(serverInstanceNo: string, privateKey?: string) {
    const params: any = { serverInstanceNo };
    if (privateKey) params.privateKey = privateKey;
    return await this.request("GET", "/vserver/v2", "/getRootPassword", params);
  }

  // ===== Server Image / Spec 조회 APIs =====

  async getServerImageList(params?: {
    regionCode?: string;
    hypervisorTypeCode?: string; // XEN | KVM
    platformTypeCodeList?: string;
    pageNo?: string;
    pageSize?: string;
  }) {
    return await this.request("GET", "/vserver/v2", "/getServerImageList", params || {});
  }

  async getServerSpecList(params?: {
    regionCode?: string;
    serverImageNo?: string;
    hypervisorTypeCodeList?: string;
  }) {
    return await this.request("GET", "/vserver/v2", "/getServerSpecList", params || {});
  }

  // ===== Block Storage APIs =====

  async listBlockStorages(params?: {
    regionCode?: string;
    serverInstanceNo?: string;
    blockStorageName?: string;
    blockStorageInstanceStatusCode?: string;
    pageNo?: string;
    pageSize?: string;
  }) {
    return await this.request("GET", "/vserver/v2", "/getBlockStorageInstanceList", params || {});
  }

  async createBlockStorage(params: {
    blockStorageName?: string;
    blockStorageSize: string;    // GB 단위
    serverInstanceNo: string;
    blockStorageVolumeTypeCode?: string; // SSD | HDD | CB1 | CB2
    blockStorageSnapshotInstanceNo?: string;
    regionCode?: string;
  }) {
    return await this.request("GET", "/vserver/v2", "/createBlockStorageInstance", params);
  }

  async deleteBlockStorage(blockStorageInstanceNo: string) {
    return await this.request("GET", "/vserver/v2", "/deleteBlockStorageInstances", {
      "blockStorageInstanceNoList.1": blockStorageInstanceNo,
    });
  }

  async attachBlockStorage(serverInstanceNo: string, blockStorageInstanceNo: string) {
    return await this.request("GET", "/vserver/v2", "/attachBlockStorageInstance", {
      serverInstanceNo,
      blockStorageInstanceNo,
    });
  }

  async detachBlockStorage(blockStorageInstanceNo: string) {
    return await this.request("GET", "/vserver/v2", "/detachBlockStorageInstances", {
      "blockStorageInstanceNoList.1": blockStorageInstanceNo,
    });
  }

  async changeBlockStorageVolumeSize(blockStorageInstanceNo: string, blockStorageSize: string) {
    return await this.request("GET", "/vserver/v2", "/changeBlockStorageVolumeSize", {
      blockStorageInstanceNo,
      blockStorageSize,
    });
  }

  // ===== Snapshot APIs =====

  async listSnapshots(params?: {
    regionCode?: string;
    blockStorageSnapshotName?: string;
    originalBlockStorageInstanceNo?: string;
    pageNo?: string;
    pageSize?: string;
  }) {
    return await this.request("GET", "/vserver/v2", "/getBlockStorageSnapshotInstanceList", params || {});
  }

  async createSnapshot(params: {
    blockStorageInstanceNo: string;
    blockStorageSnapshotName?: string;
    blockStorageSnapshotDescription?: string;
    regionCode?: string;
  }) {
    return await this.request("GET", "/vserver/v2", "/createBlockStorageSnapshotInstance", params);
  }

  async deleteSnapshot(blockStorageSnapshotInstanceNo: string) {
    return await this.request("GET", "/vserver/v2", "/deleteBlockStorageSnapshotInstances", {
      "blockStorageSnapshotInstanceNoList.1": blockStorageSnapshotInstanceNo,
    });
  }

  // ===== Public IP APIs =====

  async listPublicIps(params?: {
    regionCode?: string;
    isAssociated?: string; // true | false
    pageNo?: string;
    pageSize?: string;
  }) {
    return await this.request("GET", "/vserver/v2", "/getPublicIpInstanceList", params || {});
  }

  async createPublicIp(params?: {
    serverInstanceNo?: string;
    regionCode?: string;
  }) {
    return await this.request("GET", "/vserver/v2", "/createPublicIpInstance", params || {});
  }

  async associatePublicIp(publicIpInstanceNo: string, serverInstanceNo: string) {
    return await this.request("GET", "/vserver/v2", "/associatePublicIpWithServerInstance", {
      publicIpInstanceNo,
      serverInstanceNo,
    });
  }

  async disassociatePublicIp(publicIpInstanceNo: string) {
    return await this.request("GET", "/vserver/v2", "/disassociatePublicIpFromServerInstance", {
      publicIpInstanceNo,
    });
  }

  async deletePublicIp(publicIpInstanceNo: string) {
    return await this.request("GET", "/vserver/v2", "/deletePublicIpInstance", {
      publicIpInstanceNo,
    });
  }

  // ===== Init Script APIs =====

  async listInitScripts(params?: {
    regionCode?: string;
    initScriptName?: string;
    osTypeCode?: string; // LNX | WND
    pageNo?: string;
    pageSize?: string;
  }) {
    return await this.request("GET", "/vserver/v2", "/getInitScriptList", params || {});
  }

  async createInitScript(params: {
    initScriptContent: string;
    initScriptName?: string;
    initScriptDescription?: string;
    osTypeCode?: string; // LNX | WND
    regionCode?: string;
  }) {
    return await this.request("GET", "/vserver/v2", "/createInitScript", params);
  }

  async deleteInitScript(initScriptNo: string) {
    return await this.request("GET", "/vserver/v2", "/deleteInitScripts", {
      "initScriptNoList.1": initScriptNo,
    });
  }

  // ===== Network Interface APIs =====

  async listNetworkInterfaces(params?: {
    regionCode?: string;
    vpcNo?: string;
    subnetNo?: string;
    networkInterfaceName?: string;
    networkInterfaceStatusCode?: string; // NOTUSED | USED
    serverInstanceNo?: string;
    pageNo?: string;
    pageSize?: string;
  }) {
    return await this.request("GET", "/vserver/v2", "/getNetworkInterfaceList", params || {});
  }

  async createNetworkInterface(params: {
    vpcNo: string;
    subnetNo: string;
    "accessControlGroupNoList.1": string;
    networkInterfaceName?: string;
    ip?: string;
    networkInterfaceDescription?: string;
    regionCode?: string;
  }) {
    return await this.request("GET", "/vserver/v2", "/createNetworkInterface", params);
  }

  async deleteNetworkInterface(networkInterfaceNo: string) {
    return await this.request("GET", "/vserver/v2", "/deleteNetworkInterface", {
      networkInterfaceNo,
    });
  }

  async attachNetworkInterface(networkInterfaceNo: string, serverInstanceNo: string, networkInterfaceOrder: string) {
    return await this.request("GET", "/vserver/v2", "/attachNetworkInterface", {
      networkInterfaceNo,
      serverInstanceNo,
      networkInterfaceOrder,
    });
  }

  async detachNetworkInterface(networkInterfaceNo: string, serverInstanceNo: string) {
    return await this.request("GET", "/vserver/v2", "/detachNetworkInterface", {
      networkInterfaceNo,
      serverInstanceNo,
    });
  }

  // ===== VPC APIs =====
  // [버그 수정] VPC/Subnet API 경로는 /vpc/v2 (기존 /vserver/v2 잘못됨)

  async listVpcs() {
    return await this.request("GET", "/vpc/v2", "/getVpcList", {});
  }

  async getVpcDetail(vpcNo: string) {
    return await this.request("GET", "/vpc/v2", "/getVpcDetail", { vpcNo });
  }

  async createVpc(params: {
    vpcName: string;
    ipv4CidrBlock: string;
  }) {
    return await this.request("GET", "/vpc/v2", "/createVpc", params);
  }

  async deleteVpc(vpcNo: string) {
    return await this.request("GET", "/vpc/v2", "/deleteVpc", { vpcNo });
  }

  // ===== Subnet APIs =====

  async listSubnets(vpcNo?: string) {
    const params: any = {};
    if (vpcNo) params.vpcNo = vpcNo;
    return await this.request("GET", "/vpc/v2", "/getSubnetList", params);
  }

  async getSubnetDetail(subnetNo: string) {
    return await this.request("GET", "/vpc/v2", "/getSubnetDetail", { subnetNo });
  }

  async createSubnet(params: {
    subnetName: string;
    vpcNo: string;
    subnet: string;
    zoneCode: string;
    networkAclNo: string;
    subnetTypeCode: string; // PUBLIC | PRIVATE
  }) {
    return await this.request("GET", "/vpc/v2", "/createSubnet", params);
  }

  async deleteSubnet(subnetNo: string) {
    return await this.request("GET", "/vpc/v2", "/deleteSubnet", { subnetNo });
  }

  // ===== Network ACL APIs =====

  async listNetworkAcls(params?: { vpcNo?: string; networkAclName?: string }) {
    return await this.request("GET", "/vpc/v2", "/getNetworkAclList", params || {});
  }

  async getNetworkAclDetail(networkAclNo: string) {
    return await this.request("GET", "/vpc/v2", "/getNetworkAclDetail", { networkAclNo });
  }

  async createNetworkAcl(params: {
    vpcNo: string;
    networkAclName?: string;
    networkAclDescription?: string;
  }) {
    return await this.request("GET", "/vpc/v2", "/createNetworkAcl", params);
  }

  async deleteNetworkAcl(networkAclNo: string) {
    return await this.request("GET", "/vpc/v2", "/deleteNetworkAcl", { networkAclNo });
  }

  async setSubnetNetworkAcl(params: { subnetNo: string; networkAclNo: string }) {
    return await this.request("GET", "/vpc/v2", "/setSubnetNetworkAcl", params);
  }

  async getNetworkAclRuleList(networkAclNo: string) {
    return await this.request("GET", "/vpc/v2", "/getNetworkAclRuleList", { networkAclNo });
  }

  async addNetworkAclInboundRule(params: {
    networkAclNo: string;
    "networkAclRuleList.1.priority": string;          // 1~199
    "networkAclRuleList.1.protocolTypeCode": string;  // TCP | UDP | ICMP
    "networkAclRuleList.1.ipBlock": string;
    "networkAclRuleList.1.ruleActionCode": string;    // ALLOW | DROP
    "networkAclRuleList.1.portRange"?: string;
  }) {
    return await this.request("POST", "/vpc/v2", "/addNetworkAclInboundRule", params);
  }

  async addNetworkAclOutboundRule(params: {
    networkAclNo: string;
    "networkAclRuleList.1.priority": string;
    "networkAclRuleList.1.protocolTypeCode": string;
    "networkAclRuleList.1.ipBlock": string;
    "networkAclRuleList.1.ruleActionCode": string;
    "networkAclRuleList.1.portRange"?: string;
  }) {
    return await this.request("POST", "/vpc/v2", "/addNetworkAclOutboundRule", params);
  }

  async removeNetworkAclInboundRule(params: {
    networkAclNo: string;
    "networkAclRuleList.1.priority": string;
    "networkAclRuleList.1.protocolTypeCode": string;
    "networkAclRuleList.1.ipBlock": string;
    "networkAclRuleList.1.ruleActionCode": string;
    "networkAclRuleList.1.portRange"?: string;
  }) {
    return await this.request("POST", "/vpc/v2", "/removeNetworkAclInboundRule", params);
  }

  async removeNetworkAclOutboundRule(params: {
    networkAclNo: string;
    "networkAclRuleList.1.priority": string;
    "networkAclRuleList.1.protocolTypeCode": string;
    "networkAclRuleList.1.ipBlock": string;
    "networkAclRuleList.1.ruleActionCode": string;
    "networkAclRuleList.1.portRange"?: string;
  }) {
    return await this.request("POST", "/vpc/v2", "/removeNetworkAclOutboundRule", params);
  }

  // ===== NAT Gateway APIs =====

  async listNatGatewayInstances(params?: { vpcNo?: string; natGatewayName?: string; publicIp?: string }) {
    return await this.request("GET", "/vpc/v2", "/getNatGatewayInstanceList", params || {});
  }

  async getNatGatewayInstanceDetail(natGatewayInstanceNo: string) {
    return await this.request("GET", "/vpc/v2", "/getNatGatewayInstanceDetail", { natGatewayInstanceNo });
  }

  async createNatGatewayInstance(params: {
    vpcNo: string;
    subnetNo: string;
    natGatewayName?: string;
    natGatewayDescription?: string;
  }) {
    return await this.request("GET", "/vpc/v2", "/createNatGatewayInstance", params);
  }

  async deleteNatGatewayInstance(natGatewayInstanceNo: string) {
    return await this.request("GET", "/vpc/v2", "/deleteNatGatewayInstance", { natGatewayInstanceNo });
  }

  // ===== Route Table APIs =====

  async listRouteTables(params?: { vpcNo?: string; routeTableName?: string; supportedSubnetTypeCode?: string }) {
    return await this.request("GET", "/vpc/v2", "/getRouteTableList", params || {});
  }

  async getRouteTableDetail(routeTableNo: string) {
    return await this.request("GET", "/vpc/v2", "/getRouteTableDetail", { routeTableNo });
  }

  async createRouteTable(params: {
    vpcNo: string;
    routeTableName?: string;
    supportedSubnetTypeCode: string; // PUBLIC | PRIVATE
    routeTableDescription?: string;
  }) {
    return await this.request("GET", "/vpc/v2", "/createRouteTable", params);
  }

  async deleteRouteTable(routeTableNo: string) {
    return await this.request("GET", "/vpc/v2", "/deleteRouteTable", { routeTableNo });
  }

  async getRouteList(routeTableNo: string) {
    return await this.request("GET", "/vpc/v2", "/getRouteList", { routeTableNo });
  }

  async addRoute(params: {
    routeTableNo: string;
    "routeList.1.destinationCidrBlock": string;
    "routeList.1.targetTypeCode": string;   // NATGW | VPCPEERING | IGW
    "routeList.1.targetNo": string;
    "routeList.1.targetName": string;
  }) {
    return await this.request("POST", "/vpc/v2", "/addRoute", params);
  }

  async removeRoute(params: {
    routeTableNo: string;
    "routeList.1.destinationCidrBlock": string;
    "routeList.1.targetTypeCode": string;
    "routeList.1.targetNo": string;
    "routeList.1.targetName": string;
  }) {
    return await this.request("POST", "/vpc/v2", "/removeRoute", params);
  }

  async getRouteTableSubnetList(routeTableNo: string) {
    return await this.request("GET", "/vpc/v2", "/getRouteTableSubnetList", { routeTableNo });
  }

  async addRouteTableSubnet(params: {
    routeTableNo: string;
    "subnetNoList.1": string;
  }) {
    return await this.request("POST", "/vpc/v2", "/addRouteTableSubnet", params);
  }

  async removeRouteTableSubnet(params: {
    routeTableNo: string;
    "subnetNoList.1": string;
  }) {
    return await this.request("POST", "/vpc/v2", "/removeRouteTableSubnet", params);
  }

  // ===== VPC Peering APIs =====

  async listVpcPeeringInstances(params?: { vpcNo?: string; vpcPeeringName?: string }) {
    return await this.request("GET", "/vpc/v2", "/getVpcPeeringInstanceList", params || {});
  }

  async createVpcPeeringInstance(params: {
    sourceVpcNo: string;
    targetVpcNo: string;
    vpcPeeringName?: string;
    vpcPeeringDescription?: string;
  }) {
    return await this.request("GET", "/vpc/v2", "/createVpcPeeringInstance", params);
  }

  async deleteVpcPeeringInstance(vpcPeeringInstanceNo: string) {
    return await this.request("GET", "/vpc/v2", "/deleteVpcPeeringInstance", { vpcPeeringInstanceNo });
  }

  async acceptOrRejectVpcPeering(params: {
    vpcPeeringInstanceNo: string;
    isAccept: string; // true | false
  }) {
    return await this.request("GET", "/vpc/v2", "/acceptOrRejectVpcPeering", params);
  }

  // ===== ACG (Access Control Group) APIs =====

  async listAcgs(vpcNo?: string) {
    const params: any = {};
    if (vpcNo) params.vpcNo = vpcNo;
    return await this.request("GET", "/vserver/v2", "/getAccessControlGroupList", params);
  }

  async createAcg(params: {
    accessControlGroupName: string;
    vpcNo: string;
    accessControlGroupDescription?: string;
  }) {
    return await this.request("GET", "/vserver/v2", "/createAccessControlGroup", params);
  }

  async deleteAcg(accessControlGroupNo: string) {
    return await this.request("GET", "/vserver/v2", "/deleteAccessControlGroup", {
      accessControlGroupNo,
    });
  }

  async getAcgRuleList(accessControlGroupNo: string) {
    return await this.request("GET", "/vserver/v2", "/getAccessControlGroupRuleList", {
      accessControlGroupNo,
    });
  }

  async addAcgInboundRule(params: {
    vpcNo: string;
    accessControlGroupNo: string;
    "accessControlGroupRuleList.1.protocolTypeCode": string; // TCP | UDP | ICMP
    "accessControlGroupRuleList.1.ipBlock"?: string;
    "accessControlGroupRuleList.1.portRange"?: string;
    "accessControlGroupRuleList.1.accessControlGroupSequence"?: string;
  }) {
    return await this.request("POST", "/vserver/v2", "/addAccessControlGroupInboundRule", params);
  }

  async addAcgOutboundRule(params: {
    vpcNo: string;
    accessControlGroupNo: string;
    "accessControlGroupRuleList.1.protocolTypeCode": string;
    "accessControlGroupRuleList.1.ipBlock"?: string;
    "accessControlGroupRuleList.1.portRange"?: string;
  }) {
    return await this.request("POST", "/vserver/v2", "/addAccessControlGroupOutboundRule", params);
  }

  async removeAcgInboundRule(params: {
    vpcNo: string;
    accessControlGroupNo: string;
    "accessControlGroupRuleList.1.protocolTypeCode": string;
    "accessControlGroupRuleList.1.ipBlock"?: string;
    "accessControlGroupRuleList.1.portRange"?: string;
  }) {
    return await this.request("POST", "/vserver/v2", "/removeAccessControlGroupInboundRule", params);
  }

  async removeAcgOutboundRule(params: {
    vpcNo: string;
    accessControlGroupNo: string;
    "accessControlGroupRuleList.1.protocolTypeCode": string;
    "accessControlGroupRuleList.1.ipBlock"?: string;
    "accessControlGroupRuleList.1.portRange"?: string;
  }) {
    return await this.request("POST", "/vserver/v2", "/removeAccessControlGroupOutboundRule", params);
  }

  // ===== Load Balancer APIs =====

  async listLoadBalancers(params?: {
    vpcNo?: string;
    loadBalancerName?: string;
    loadBalancerTypeCode?: string; // APPLICATION | NETWORK | NETWORK_PROXY
  }) {
    return await this.request("GET", "/vloadbalancer/v2", "/getLoadBalancerInstanceList", params || {});
  }

  async getLoadBalancerInstanceDetail(loadBalancerInstanceNo: string) {
    return await this.request("GET", "/vloadbalancer/v2", "/getLoadBalancerInstanceDetail", {
      loadBalancerInstanceNo,
    });
  }

  async createLoadBalancer(params: {
    loadBalancerName: string;
    loadBalancerTypeCode: string;             // APPLICATION | NETWORK | NETWORK_PROXY
    loadBalancerNetworkTypeCode: string;      // PUBLIC | PRIVATE
    vpcNo: string;
    "subnetNoList.1": string;
    "loadBalancerListenerList.1.protocolTypeCode": string;  // APPLICATION: HTTP|HTTPS / NETWORK: TCP|UDP / NETWORK_PROXY: TCP|TLS
    "loadBalancerListenerList.1.port": string;
    "loadBalancerListenerList.1.targetGroupNo": string;
    idleTimeout?: string;                     // 초 단위 1~3600 (기본값: 60, NETWORK 타입 불가)
    throughputTypeCode?: string;              // SMALL|MEDIUM|LARGE|XLARGE (APPLICATION/NETWORK_PROXY) | DYNAMIC (NETWORK)
    loadBalancerDescription?: string;
  }) {
    return await this.request("GET", "/vloadbalancer/v2", "/createLoadBalancerInstance", params);
  }

  async changeLoadBalancerInstanceConfiguration(params: {
    loadBalancerInstanceNo: string;
    idleTimeout?: string;
    throughputTypeCode?: string;
  }) {
    return await this.request("GET", "/vloadbalancer/v2", "/changeLoadBalancerInstanceConfiguration", params);
  }

  async setLoadBalancerDescription(params: {
    loadBalancerInstanceNo: string;
    loadBalancerDescription: string;
  }) {
    return await this.request("GET", "/vloadbalancer/v2", "/setLoadBalancerDescription", params);
  }

  async setLoadBalancerInstanceSubnet(params: {
    loadBalancerInstanceNo: string;
    "subnetNoList.1": string;
  }) {
    return await this.request("GET", "/vloadbalancer/v2", "/setLoadBalancerInstanceSubnet", params);
  }

  async deleteLoadBalancer(loadBalancerInstanceNo: string) {
    return await this.request("GET", "/vloadbalancer/v2", "/deleteLoadBalancerInstances", {
      "loadBalancerInstanceNoList.1": loadBalancerInstanceNo,
    });
  }

  // ===== Load Balancer Listener APIs =====

  async getLoadBalancerListenerList(loadBalancerInstanceNo: string) {
    return await this.request("GET", "/vloadbalancer/v2", "/getLoadBalancerListenerList", {
      loadBalancerInstanceNo,
    });
  }

  async createLoadBalancerListener(params: {
    loadBalancerInstanceNo: string;
    protocolTypeCode: string;        // HTTP | HTTPS | TCP | UDP | TLS
    port: string;                    // 1~65534
    targetGroupNo: string;
    useHttp2?: string;               // true | false (HTTPS만)
    sslCertificateNo?: string;       // HTTPS | TLS 필수
    tlsMinVersionTypeCode?: string;  // TLSV10 | TLSV11 | TLSV12
  }) {
    return await this.request("GET", "/vloadbalancer/v2", "/createLoadBalancerListener", params);
  }

  async changeLoadBalancerListenerConfiguration(params: {
    loadBalancerListenerNo: string;
    protocolTypeCode: string;        // HTTP | HTTPS | TCP | UDP | TLS (Required)
    port: string;                    // 1~65534 (Required)
    useHttp2?: string;               // true | false (HTTPS만)
    sslCertificateNo?: string;       // HTTPS | TLS 필수
    tlsMinVersionTypeCode?: string;  // TLSV10 | TLSV11 | TLSV12
  }) {
    return await this.request("GET", "/vloadbalancer/v2", "/changeLoadBalancerListenerConfiguration", params);
  }

  async deleteLoadBalancerListeners(loadBalancerListenerNo: string) {
    return await this.request("GET", "/vloadbalancer/v2", "/deleteLoadBalancerListeners", {
      "loadBalancerListenerNoList.1": loadBalancerListenerNo,
    });
  }

  async getLoadBalancerRuleList(loadBalancerListenerNo: string) {
    return await this.request("GET", "/vloadbalancer/v2", "/getLoadBalancerRuleList", {
      loadBalancerListenerNo,
    });
  }

  // ===== Target Group APIs =====

  async listTargetGroups(params?: {
    vpcNo?: string;
    targetGroupName?: string;
    targetTypeCode?: string; // VSVR | SERVERGROUP
  }) {
    return await this.request("GET", "/vloadbalancer/v2", "/getTargetGroupList", params || {});
  }

  async getTargetGroupDetail(targetGroupNo: string) {
    return await this.request("GET", "/vloadbalancer/v2", "/getTargetGroupDetail", {
      targetGroupNo,
    });
  }

  async createTargetGroup(params: {
    vpcNo: string;
    targetGroupName?: string;                  // Optional (자동 부여)
    targetTypeCode?: string;                   // VSVR (기본값)
    targetGroupProtocolTypeCode: string;       // HTTP | HTTPS | TCP | UDP | PROXY_TCP (Required)
    targetGroupPort?: string;                  // 1~65534 (기본값: 80)
    targetGroupDescription?: string;
    healthCheckProtocolTypeCode: string;       // HTTP | HTTPS | TCP (Required)
    healthCheckPort?: string;                  // 1~65534 (기본값: 80)
    healthCheckUrlPath?: string;               // HTTP | HTTPS 헬스체크 시 사용
    healthCheckHttpMethodTypeCode?: string;    // HEAD | GET — HTTP | HTTPS 헬스체크 시 필수
    healthCheckCycle?: string;                 // 5~300 (기본값: 30)
    healthCheckUpThreshold?: string;           // 2~10 (기본값: 2)
    healthCheckDownThreshold?: string;         // 2~10 (기본값: 2)
    "targetNoList.1"?: string;                 // 생성 시 바로 타깃 바인딩 (선택)
  }) {
    return await this.request("GET", "/vloadbalancer/v2", "/createTargetGroup", params);
  }

  async changeTargetGroupConfiguration(params: {
    targetGroupNo: string;
    useStickySession?: string;     // true | false (TCP/UDP/HTTP/HTTPS만)
    useProxyProtocol?: string;     // true | false (PROXY_TCP만)
    algorithmTypeCode?: string;    // RR | SIPHS | LC | MH
  }) {
    return await this.request("GET", "/vloadbalancer/v2", "/changeTargetGroupConfiguration", params);
  }

  async changeTargetGroupHealthCheckConfiguration(params: {
    targetGroupNo: string;
    healthCheckProtocolTypeCode?: string;
    healthCheckPort?: string;
    healthCheckUrlPath?: string;
    healthCheckHttpMethodTypeCode?: string;
    healthCheckCycle?: string;
    healthCheckUpThreshold?: string;
    healthCheckDownThreshold?: string;
  }) {
    return await this.request("GET", "/vloadbalancer/v2", "/changeTargetGroupHealthCheckConfiguration", params);
  }

  async setTargetGroupDescription(params: {
    targetGroupNo: string;
    targetGroupDescription: string;
  }) {
    return await this.request("GET", "/vloadbalancer/v2", "/setTargetGroupDescription", params);
  }

  async deleteTargetGroups(targetGroupNo: string) {
    return await this.request("GET", "/vloadbalancer/v2", "/deleteTargetGroups", {
      "targetGroupNoList.1": targetGroupNo,
    });
  }

  async getTargetList(targetGroupNo: string) {
    return await this.request("GET", "/vloadbalancer/v2", "/getTargetList", {
      targetGroupNo,
    });
  }

  async addTarget(params: {
    targetGroupNo: string;
    "targetNoList.1": string;
  }) {
    return await this.request("GET", "/vloadbalancer/v2", "/addTarget", params);
  }

  async removeTarget(params: {
    targetGroupNo: string;
    "targetNoList.1": string;
  }) {
    return await this.request("GET", "/vloadbalancer/v2", "/removeTarget", params);
  }

  // ===== Cloud DB (MySQL) APIs =====

  async listCloudDBInstances() {
    return await this.request("GET", "/vmysql/v2", "/getCloudMysqlInstanceList", {});
  }

  async createCloudDB(params: {
    vpcNo: string;
    subnetNo: string;
    cloudMysqlServiceName: string;
    cloudMysqlServerNamePrefix: string;
    cloudMysqlUserName: string;
    cloudMysqlUserPassword: string;
    hostIp: string;
    cloudMysqlDatabaseName: string;
    cloudMysqlImageProductCode?: string;
    cloudMysqlProductCode?: string;
    dataStorageTypeCode?: string;
    isHa?: boolean;
    isMultiZone?: boolean;
    isStorageEncryption?: boolean;
    isBackup?: boolean;
    backupFileRetentionPeriod?: number;
    backupTime?: string;
    isAutomaticBackup?: boolean;
    cloudMysqlPort?: number;
    standbyMasterSubnetNo?: string;
    regionCode?: string;
  }) {
    return await this.request("GET", "/vmysql/v2", "/createCloudMysqlInstance", params);
  }

  async deleteCloudDB(cloudMysqlInstanceNo: string) {
    return await this.request("GET", "/vmysql/v2", "/deleteCloudMysqlInstance", {
      cloudMysqlInstanceNo,
    });
  }

  async listCloudDBMysqlInstances() {
    return await this.request("GET", "/vmysql/v2", "/getCloudMysqlInstanceList", {});
  }

  async getCloudDBMysqlDetail(cloudMysqlInstanceNo: string) {
    return await this.request("GET", "/vmysql/v2", "/getCloudMysqlInstanceDetail", {
      cloudMysqlInstanceNo,
    });
  }

  // ===== Cloud DB Database APIs =====

  async getCloudMysqlDatabaseList(cloudMysqlInstanceNo: string) {
    return await this.request("GET", "/vmysql/v2", "/getCloudMysqlDatabaseList", {
      cloudMysqlInstanceNo,
    });
  }

  async addCloudMysqlDatabase(params: {
    cloudMysqlInstanceNo: string;
    "cloudMysqlDatabaseNameList.1": string;
  }) {
    return await this.request("POST", "/vmysql/v2", "/addCloudMysqlDatabaseList", params);
  }

  async deleteCloudMysqlDatabase(params: {
    cloudMysqlInstanceNo: string;
    "cloudMysqlDatabaseNameList.1": string;
  }) {
    return await this.request("POST", "/vmysql/v2", "/deleteCloudMysqlDatabaseList", params);
  }

  // ===== Cloud DB User APIs =====

  async getCloudMysqlUserList(cloudMysqlInstanceNo: string) {
    return await this.request("GET", "/vmysql/v2", "/getCloudMysqlUserList", {
      cloudMysqlInstanceNo,
    });
  }

  async addCloudMysqlUser(params: {
    cloudMysqlInstanceNo: string;
    "cloudMysqlUserList.1.name": string;
    "cloudMysqlUserList.1.password": string;
    "cloudMysqlUserList.1.hostIp": string;
    "cloudMysqlUserList.1.authority": string; // READ | CRUD | DDL
    "cloudMysqlUserList.1.isSystemTableAccess"?: string; // true | false
  }) {
    return await this.request("POST", "/vmysql/v2", "/addCloudMysqlUserList", params);
  }

  async deleteCloudMysqlUser(params: {
    cloudMysqlInstanceNo: string;
    "cloudMysqlUserList.1.name": string;
    "cloudMysqlUserList.1.hostIp": string;
  }) {
    return await this.request("POST", "/vmysql/v2", "/deleteCloudMysqlUserList", params);
  }

  // ===== Ncloud Object Storage (S3 호환) APIs =====
  // 인증: AWS Signature Version 4 (NCP API와 별도)
  // 엔드포인트: https://{bucket}.kr.ncloudstorage.com 또는 https://kr.ncloudstorage.com

  private generateAwsSignatureV4(
    method: string,
    host: string,
    path: string,
    queryString: string,
    headers: Record<string, string>,
    body: string,
    date: string,
    datetime: string
  ): string {
    const region = "kr";
    const service = "s3";

    // 1. Canonical Request
    const canonicalHeaders = Object.entries(headers)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k.toLowerCase()}:${v.trim()}`)
      .join("\n") + "\n";
    const signedHeaders = Object.keys(headers)
      .sort()
      .map(k => k.toLowerCase())
      .join(";");
    const payloadHash = crypto.createHash("sha256").update(body).digest("hex");
    const canonicalRequest = [method, path, queryString, canonicalHeaders, signedHeaders, payloadHash].join("\n");

    // 2. String to Sign
    const credentialScope = `${date}/${region}/${service}/aws4_request`;
    const stringToSign = [
      "AWS4-HMAC-SHA256",
      datetime,
      credentialScope,
      crypto.createHash("sha256").update(canonicalRequest).digest("hex"),
    ].join("\n");

    // 3. Signing Key
    const hmac = (key: Buffer | string, data: string) =>
      crypto.createHmac("sha256", key).update(data).digest();
    const signingKey = hmac(
      hmac(hmac(hmac(`AWS4${this.secretKey}`, date), region), service),
      "aws4_request"
    );

    return hmac(signingKey, stringToSign).toString("hex");
  }

  private async storageRequest(
    method: string,
    bucket: string | null,
    objectKey: string,
    queryParams: Record<string, string> = {},
    body: string = "",
    extraHeaders: Record<string, string> = {}
  ) {
    const region = "kr";
    const host = bucket
      ? `${bucket}.${region}.ncloudstorage.com`
      : `${region}.ncloudstorage.com`;
    const path = objectKey.startsWith("/") ? objectKey : `/${objectKey}`;
    const now = new Date();
    const datetime = now.toISOString().replace(/[-:]/g, "").split(".")[0] + "Z";
    const date = datetime.slice(0, 8);

    const queryString = Object.entries(queryParams)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&");

    const payloadHash = crypto.createHash("sha256").update(body).digest("hex");
    const headers: Record<string, string> = {
      Host: host,
      "x-amz-date": datetime,
      "x-amz-content-sha256": payloadHash,
      ...extraHeaders,
    };
    if (body) headers["Content-Length"] = String(Buffer.byteLength(body));

    const signature = this.generateAwsSignatureV4(
      method, host, path, queryString, headers, body, date, datetime
    );

    const signedHeaders = Object.keys(headers).sort().map(k => k.toLowerCase()).join(";");
    const credentialScope = `${date}/kr/s3/aws4_request`;
    const authorization = `AWS4-HMAC-SHA256 Credential=${this.accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const url = `https://${host}${path}${queryString ? "?" + queryString : ""}`;

    try {
      const response = await axios({
        method,
        url,
        headers: { ...headers, Authorization: authorization },
        data: body || undefined,
        httpsAgent: new https.Agent({ rejectUnauthorized: false }),
        responseType: "text",
      });
      return response.data;
    } catch (error: any) {
      throw new Error(`Storage API Error: ${error.response?.data || error.message}`);
    }
  }

  // ----- Bucket -----

  async listBuckets() {
    return await this.storageRequest("GET", null, "/");
  }

  async createBucket(bucket: string) {
    return await this.storageRequest("PUT", bucket, "/");
  }

  async deleteBucket(bucket: string) {
    return await this.storageRequest("DELETE", bucket, "/");
  }

  async headBucket(bucket: string) {
    return await this.storageRequest("HEAD", bucket, "/");
  }

  async getBucketLocation(bucket: string) {
    return await this.storageRequest("GET", bucket, "/", { location: "" });
  }

  async getBucketVersioning(bucket: string) {
    return await this.storageRequest("GET", bucket, "/", { versioning: "" });
  }

  async putBucketVersioning(bucket: string, status: "Enabled" | "Suspended") {
    const body = `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>${status}</Status></VersioningConfiguration>`;
    return await this.storageRequest("PUT", bucket, "/", { versioning: "" }, body, {
      "Content-Type": "application/xml",
    });
  }

  async getBucketLifecycleConfiguration(bucket: string) {
    return await this.storageRequest("GET", bucket, "/", { lifecycle: "" });
  }

  async deleteBucketLifecycle(bucket: string) {
    return await this.storageRequest("DELETE", bucket, "/", { lifecycle: "" });
  }

  async getBucketEncryption(bucket: string) {
    return await this.storageRequest("GET", bucket, "/", { encryption: "" });
  }

  // ----- Object -----

  async listObjects(bucket: string, params?: {
    prefix?: string;
    delimiter?: string;
    maxKeys?: string;
    marker?: string;
  }) {
    return await this.storageRequest("GET", bucket, "/", params as Record<string, string> || {});
  }

  async listObjectsV2(bucket: string, params?: {
    prefix?: string;
    delimiter?: string;
    "max-keys"?: string;
    "continuation-token"?: string;
    "start-after"?: string;
  }) {
    return await this.storageRequest("GET", bucket, "/", { "list-type": "2", ...(params || {}) });
  }

  async listObjectVersions(bucket: string, params?: {
    prefix?: string;
    delimiter?: string;
    "key-marker"?: string;
    "version-id-marker"?: string;
  }) {
    return await this.storageRequest("GET", bucket, "/", { versions: "", ...(params || {}) });
  }

  async headObject(bucket: string, objectKey: string) {
    return await this.storageRequest("HEAD", bucket, `/${objectKey}`);
  }

  async getObject(bucket: string, objectKey: string, versionId?: string) {
    const params: Record<string, string> = {};
    if (versionId) params.versionId = versionId;
    return await this.storageRequest("GET", bucket, `/${objectKey}`, params);
  }

  async putObject(bucket: string, objectKey: string, body: string, contentType: string = "application/octet-stream") {
    return await this.storageRequest("PUT", bucket, `/${objectKey}`, {}, body, {
      "Content-Type": contentType,
    });
  }

  async copyObject(sourceBucket: string, sourceKey: string, destBucket: string, destKey: string) {
    return await this.storageRequest("PUT", destBucket, `/${destKey}`, {}, "", {
      "x-amz-copy-source": `/${sourceBucket}/${sourceKey}`,
    });
  }

  async deleteObject(bucket: string, objectKey: string, versionId?: string) {
    const params: Record<string, string> = {};
    if (versionId) params.versionId = versionId;
    return await this.storageRequest("DELETE", bucket, `/${objectKey}`, params);
  }

  // ----- Multipart Upload -----

  async createMultipartUpload(bucket: string, objectKey: string, contentType: string = "application/octet-stream") {
    return await this.storageRequest("POST", bucket, `/${objectKey}`, { uploads: "" }, "", {
      "Content-Type": contentType,
    });
  }

  async listMultipartUploads(bucket: string, params?: { prefix?: string; delimiter?: string }) {
    return await this.storageRequest("GET", bucket, "/", { uploads: "", ...(params || {}) });
  }

  async listParts(bucket: string, objectKey: string, uploadId: string) {
    return await this.storageRequest("GET", bucket, `/${objectKey}`, { uploadId });
  }

  async abortMultipartUpload(bucket: string, objectKey: string, uploadId: string) {
    return await this.storageRequest("DELETE", bucket, `/${objectKey}`, { uploadId });
  }
}

// MCP 서버 설정
const server = new Server(
  {
    name: "ncp-compute-server",
    version: "3.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

const accessKey = process.env.NCP_ACCESS_KEY;
const secretKey = process.env.NCP_SECRET_KEY;

if (!accessKey || !secretKey) {
  console.error("Error: NCP_ACCESS_KEY and NCP_SECRET_KEY must be set");
  process.exit(1);
}

const ncpClient = new NCPClient(accessKey, secretKey);

// 도구 목록 정의
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      // ===== Server =====
      {
        name: "list_servers",
        description: "NCP의 서버 인스턴스 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            regionCode: { type: "string", description: "리전 코드 (예: KR)" },
            vpcNo: { type: "string", description: "VPC 번호로 필터링" },
            serverName: { type: "string", description: "서버 이름으로 필터링" },
            serverInstanceStatusCode: { type: "string", description: "상태 코드 (INIT | CREAT | RUN | NSTOP)" },
            pageNo: { type: "string", description: "페이지 번호 (기본값: 0)" },
            pageSize: { type: "string", description: "페이지당 항목 수 (1~1000)" },
            sortedBy: { type: "string", description: "정렬 기준 (serverName | serverInstanceNo)" },
            sortingOrder: { type: "string", description: "정렬 순서 (ASC | DESC)" },
          },
        },
      },
      {
        name: "get_server_detail",
        description: "서버 인스턴스의 상세 정보를 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            serverInstanceNo: { type: "string", description: "서버 인스턴스 번호" },
          },
          required: ["serverInstanceNo"],
        },
      },
      {
        name: "create_server",
        description: "새로운 서버 인스턴스를 생성합니다",
        inputSchema: {
          type: "object",
          properties: {
            serverImageNo: { type: "string", description: "서버 이미지 번호 (KVM/XEN/RHV 신규 이미지 사용 시)" },
            serverImageProductCode: { type: "string", description: "서버 이미지 상품 코드 (RHV/XEN 구버전 방식)" },
            memberServerImageInstanceNo: { type: "string", description: "내 커스텀 서버 이미지 번호" },
            serverSpecCode: { type: "string", description: "서버 스펙 코드 (serverImageNo 사용 시, 예: c2-g3)" },
            serverProductCode: { type: "string", description: "서버 상품 코드 (serverImageProductCode 사용 시)" },
            vpcNo: { type: "string", description: "VPC 번호" },
            subnetNo: { type: "string", description: "서브넷 번호" },
            "networkInterfaceList.1.networkInterfaceOrder": { type: "string", description: "기본 NIC 순서 (\"0\" 입력)" },
            "networkInterfaceList.1.accessControlGroupNoList.1": { type: "string", description: "적용할 ACG 번호" },
            serverName: { type: "string", description: "서버 이름 (3~30자, 영문소문자+숫자+-)" },
            serverCreateCount: { type: "string", description: "생성 수량 (1~100, 기본값: 1)" },
            serverCreateStartNo: { type: "string", description: "서버 이름 일련번호 시작값 (0~999)" },
            loginKeyName: { type: "string", description: "SSH 인증키 이름" },
            initScriptNo: { type: "string", description: "초기화 스크립트 번호" },
            feeSystemTypeCode: { type: "string", description: "요금제 (MTRAT: 시간제(기본) | FXSUM: 월정액)" },
            isProtectServerTermination: { type: "string", description: "반납 보호 여부 (true | false)" },
            associateWithPublicIp: { type: "string", description: "공인 IP 자동 할당 (true | false, Public Subnet + 1대만)" },
            placementGroupNo: { type: "string", description: "물리 배치 그룹 번호" },
            serverDescription: { type: "string", description: "서버 설명 (최대 1000 byte)" },
            regionCode: { type: "string", description: "리전 코드" },
          },
          required: ["vpcNo", "subnetNo", "networkInterfaceList.1.networkInterfaceOrder", "networkInterfaceList.1.accessControlGroupNoList.1"],
        },
      },
      {
        name: "start_server",
        description: "중지된 서버 인스턴스를 시작합니다",
        inputSchema: {
          type: "object",
          properties: {
            serverInstanceNo: { type: "string", description: "서버 인스턴스 번호" },
          },
          required: ["serverInstanceNo"],
        },
      },
      {
        name: "stop_server",
        description: "실행 중인 서버 인스턴스를 중지합니다",
        inputSchema: {
          type: "object",
          properties: {
            serverInstanceNo: { type: "string", description: "서버 인스턴스 번호" },
          },
          required: ["serverInstanceNo"],
        },
      },
      {
        name: "reboot_server",
        description: "서버 인스턴스를 재시작합니다",
        inputSchema: {
          type: "object",
          properties: {
            serverInstanceNo: { type: "string", description: "서버 인스턴스 번호" },
          },
          required: ["serverInstanceNo"],
        },
      },
      {
        name: "delete_server",
        description: "서버 인스턴스를 반납(삭제)합니다. 반드시 정지 상태여야 합니다",
        inputSchema: {
          type: "object",
          properties: {
            serverInstanceNo: { type: "string", description: "서버 인스턴스 번호" },
          },
          required: ["serverInstanceNo"],
        },
      },
      {
        name: "change_server_spec",
        description: "서버 스펙을 변경합니다. 반드시 정지 상태여야 합니다",
        inputSchema: {
          type: "object",
          properties: {
            serverInstanceNo: { type: "string", description: "서버 인스턴스 번호" },
            serverSpecCode: { type: "string", description: "변경할 서버 스펙 코드 (예: c4-g3)" },
          },
          required: ["serverInstanceNo", "serverSpecCode"],
        },
      },
      {
        name: "set_protect_server_termination",
        description: "서버 반납 보호 설정을 변경합니다",
        inputSchema: {
          type: "object",
          properties: {
            serverInstanceNo: { type: "string", description: "서버 인스턴스 번호" },
            isProtect: { type: "boolean", description: "반납 보호 여부 (true: 보호, false: 해제)" },
          },
          required: ["serverInstanceNo", "isProtect"],
        },
      },
      {
        name: "get_root_password",
        description: "서버의 root 계정 비밀번호를 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            serverInstanceNo: { type: "string", description: "서버 인스턴스 번호" },
            privateKey: { type: "string", description: "복호화용 개인키 (미입력 시 암호화된 값 반환)" },
          },
          required: ["serverInstanceNo"],
        },
      },

      // ===== Server Image / Spec =====
      {
        name: "get_server_image_list",
        description: "NCP에서 제공하는 서버 이미지 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            regionCode: { type: "string", description: "리전 코드" },
            hypervisorTypeCode: { type: "string", description: "하이퍼바이저 타입 (XEN | KVM)" },
            pageNo: { type: "string", description: "페이지 번호" },
            pageSize: { type: "string", description: "페이지당 항목 수" },
          },
        },
      },
      {
        name: "get_server_spec_list",
        description: "서버 스펙 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            regionCode: { type: "string", description: "리전 코드" },
            serverImageNo: { type: "string", description: "서버 이미지 번호" },
            hypervisorTypeCodeList: { type: "string", description: "하이퍼바이저 타입 (XEN | KVM)" },
          },
        },
      },

      // ===== Block Storage =====
      {
        name: "list_block_storages",
        description: "블록 스토리지 인스턴스 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            regionCode: { type: "string", description: "리전 코드" },
            serverInstanceNo: { type: "string", description: "서버 인스턴스 번호로 필터링" },
            blockStorageName: { type: "string", description: "스토리지 이름으로 필터링" },
            pageNo: { type: "string", description: "페이지 번호" },
            pageSize: { type: "string", description: "페이지당 항목 수" },
          },
        },
      },
      {
        name: "create_block_storage",
        description: "블록 스토리지를 생성하고 서버에 연결합니다",
        inputSchema: {
          type: "object",
          properties: {
            serverInstanceNo: { type: "string", description: "연결할 서버 인스턴스 번호" },
            blockStorageSize: { type: "string", description: "스토리지 크기 (GB, 최소 10GB)" },
            blockStorageName: { type: "string", description: "스토리지 이름" },
            blockStorageVolumeTypeCode: { type: "string", description: "볼륨 타입 (SSD | HDD | CB1 | CB2)" },
          },
          required: ["serverInstanceNo", "blockStorageSize"],
        },
      },
      {
        name: "delete_block_storage",
        description: "블록 스토리지를 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            blockStorageInstanceNo: { type: "string", description: "블록 스토리지 인스턴스 번호" },
          },
          required: ["blockStorageInstanceNo"],
        },
      },
      {
        name: "attach_block_storage",
        description: "블록 스토리지를 서버 인스턴스에 연결합니다",
        inputSchema: {
          type: "object",
          properties: {
            serverInstanceNo: { type: "string", description: "서버 인스턴스 번호" },
            blockStorageInstanceNo: { type: "string", description: "블록 스토리지 인스턴스 번호" },
          },
          required: ["serverInstanceNo", "blockStorageInstanceNo"],
        },
      },
      {
        name: "detach_block_storage",
        description: "블록 스토리지를 서버 인스턴스에서 분리합니다",
        inputSchema: {
          type: "object",
          properties: {
            blockStorageInstanceNo: { type: "string", description: "블록 스토리지 인스턴스 번호" },
          },
          required: ["blockStorageInstanceNo"],
        },
      },
      {
        name: "change_block_storage_volume_size",
        description: "블록 스토리지 크기를 변경합니다 (확장만 가능)",
        inputSchema: {
          type: "object",
          properties: {
            blockStorageInstanceNo: { type: "string", description: "블록 스토리지 인스턴스 번호" },
            blockStorageSize: { type: "string", description: "변경할 크기 (GB, 현재보다 커야 함)" },
          },
          required: ["blockStorageInstanceNo", "blockStorageSize"],
        },
      },

      // ===== Snapshot =====
      {
        name: "list_snapshots",
        description: "블록 스토리지 스냅샷 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            regionCode: { type: "string", description: "리전 코드" },
            originalBlockStorageInstanceNo: { type: "string", description: "원본 스토리지 번호로 필터링" },
            pageNo: { type: "string", description: "페이지 번호" },
            pageSize: { type: "string", description: "페이지당 항목 수" },
          },
        },
      },
      {
        name: "create_snapshot",
        description: "블록 스토리지의 스냅샷을 생성합니다",
        inputSchema: {
          type: "object",
          properties: {
            blockStorageInstanceNo: { type: "string", description: "스냅샷을 생성할 블록 스토리지 번호" },
            blockStorageSnapshotName: { type: "string", description: "스냅샷 이름" },
            blockStorageSnapshotDescription: { type: "string", description: "스냅샷 설명" },
          },
          required: ["blockStorageInstanceNo"],
        },
      },
      {
        name: "delete_snapshot",
        description: "블록 스토리지 스냅샷을 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            blockStorageSnapshotInstanceNo: { type: "string", description: "스냅샷 인스턴스 번호" },
          },
          required: ["blockStorageSnapshotInstanceNo"],
        },
      },

      // ===== Public IP =====
      {
        name: "list_public_ips",
        description: "공인 IP 인스턴스 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            regionCode: { type: "string", description: "리전 코드" },
            isAssociated: { type: "string", description: "서버 할당 여부 필터 (true | false)" },
          },
        },
      },
      {
        name: "create_public_ip",
        description: "공인 IP를 생성합니다",
        inputSchema: {
          type: "object",
          properties: {
            serverInstanceNo: { type: "string", description: "즉시 할당할 서버 인스턴스 번호 (선택)" },
            regionCode: { type: "string", description: "리전 코드" },
          },
        },
      },
      {
        name: "associate_public_ip",
        description: "공인 IP를 서버 인스턴스에 할당합니다",
        inputSchema: {
          type: "object",
          properties: {
            publicIpInstanceNo: { type: "string", description: "공인 IP 인스턴스 번호" },
            serverInstanceNo: { type: "string", description: "서버 인스턴스 번호" },
          },
          required: ["publicIpInstanceNo", "serverInstanceNo"],
        },
      },
      {
        name: "disassociate_public_ip",
        description: "서버 인스턴스에서 공인 IP 할당을 해제합니다",
        inputSchema: {
          type: "object",
          properties: {
            publicIpInstanceNo: { type: "string", description: "공인 IP 인스턴스 번호" },
          },
          required: ["publicIpInstanceNo"],
        },
      },
      {
        name: "delete_public_ip",
        description: "공인 IP 인스턴스를 삭제합니다. 반드시 해제 상태여야 합니다",
        inputSchema: {
          type: "object",
          properties: {
            publicIpInstanceNo: { type: "string", description: "공인 IP 인스턴스 번호" },
          },
          required: ["publicIpInstanceNo"],
        },
      },

      // ===== Init Script =====
      {
        name: "list_init_scripts",
        description: "초기화 스크립트 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            regionCode: { type: "string", description: "리전 코드" },
            initScriptName: { type: "string", description: "스크립트 이름으로 필터링" },
            osTypeCode: { type: "string", description: "OS 타입 (LNX | WND)" },
          },
        },
      },
      {
        name: "create_init_script",
        description: "서버 최초 부팅 시 실행할 초기화 스크립트를 생성합니다",
        inputSchema: {
          type: "object",
          properties: {
            initScriptContent: { type: "string", description: "스크립트 내용 (#!/bin/sh 등으로 시작)" },
            initScriptName: { type: "string", description: "스크립트 이름" },
            initScriptDescription: { type: "string", description: "스크립트 설명" },
            osTypeCode: { type: "string", description: "OS 타입 (LNX | WND)" },
          },
          required: ["initScriptContent"],
        },
      },
      {
        name: "delete_init_script",
        description: "초기화 스크립트를 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            initScriptNo: { type: "string", description: "초기화 스크립트 번호" },
          },
          required: ["initScriptNo"],
        },
      },

      // ===== Network Interface =====
      {
        name: "list_network_interfaces",
        description: "네트워크 인터페이스(NIC) 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            regionCode: { type: "string", description: "리전 코드" },
            vpcNo: { type: "string", description: "VPC 번호로 필터링" },
            subnetNo: { type: "string", description: "서브넷 번호로 필터링" },
            networkInterfaceStatusCode: { type: "string", description: "상태 코드 (NOTUSED | USED)" },
            serverInstanceNo: { type: "string", description: "연결된 서버 번호로 필터링" },
          },
        },
      },
      {
        name: "create_network_interface",
        description: "네트워크 인터페이스를 생성합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호" },
            subnetNo: { type: "string", description: "서브넷 번호" },
            "accessControlGroupNoList.1": { type: "string", description: "적용할 ACG 번호" },
            networkInterfaceName: { type: "string", description: "NIC 이름" },
            ip: { type: "string", description: "IP 직접 지정 (미입력 시 자동 할당)" },
          },
          required: ["vpcNo", "subnetNo", "accessControlGroupNoList.1"],
        },
      },
      {
        name: "delete_network_interface",
        description: "네트워크 인터페이스를 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            networkInterfaceNo: { type: "string", description: "네트워크 인터페이스 번호" },
          },
          required: ["networkInterfaceNo"],
        },
      },
      {
        name: "attach_network_interface",
        description: "네트워크 인터페이스를 서버 인스턴스에 연결합니다 (최대 3개)",
        inputSchema: {
          type: "object",
          properties: {
            networkInterfaceNo: { type: "string", description: "네트워크 인터페이스 번호" },
            serverInstanceNo: { type: "string", description: "서버 인스턴스 번호" },
            networkInterfaceOrder: { type: "string", description: "NIC 순서 (0~2, eth0/eth1/eth2에 대응)" },
          },
          required: ["networkInterfaceNo", "serverInstanceNo", "networkInterfaceOrder"],
        },
      },
      {
        name: "detach_network_interface",
        description: "서버 인스턴스에서 네트워크 인터페이스를 분리합니다 (기본 NIC는 분리 불가)",
        inputSchema: {
          type: "object",
          properties: {
            networkInterfaceNo: { type: "string", description: "네트워크 인터페이스 번호" },
            serverInstanceNo: { type: "string", description: "서버 인스턴스 번호" },
          },
          required: ["networkInterfaceNo", "serverInstanceNo"],
        },
      },

      // ===== VPC =====
      {
        name: "list_vpcs",
        description: "VPC 목록을 조회합니다",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "get_vpc_detail",
        description: "VPC 상세 정보를 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호" },
          },
          required: ["vpcNo"],
        },
      },
      {
        name: "create_vpc",
        description: "새로운 VPC를 생성합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcName: { type: "string", description: "VPC 이름" },
            ipv4CidrBlock: { type: "string", description: "IPv4 CIDR 블록 (예: 10.0.0.0/16)" },
          },
          required: ["vpcName", "ipv4CidrBlock"],
        },
      },
      {
        name: "delete_vpc",
        description: "VPC를 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호" },
          },
          required: ["vpcNo"],
        },
      },

      // ===== Subnet =====
      {
        name: "list_subnets",
        description: "서브넷 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호 (선택사항)" },
          },
        },
      },
      {
        name: "get_subnet_detail",
        description: "서브넷 상세 정보를 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            subnetNo: { type: "string", description: "서브넷 번호" },
          },
          required: ["subnetNo"],
        },
      },
      {
        name: "create_subnet",
        description: "새로운 서브넷을 생성합니다",
        inputSchema: {
          type: "object",
          properties: {
            subnetName: { type: "string", description: "서브넷 이름" },
            vpcNo: { type: "string", description: "VPC 번호" },
            subnet: { type: "string", description: "서브넷 CIDR (예: 10.0.1.0/24)" },
            zoneCode: { type: "string", description: "존 코드 (예: KR-1, KR-2)" },
            networkAclNo: { type: "string", description: "Network ACL 번호" },
            subnetTypeCode: { type: "string", description: "서브넷 타입 (PUBLIC | PRIVATE)" },
          },
          required: ["subnetName", "vpcNo", "subnet", "zoneCode", "networkAclNo", "subnetTypeCode"],
        },
      },
      {
        name: "delete_subnet",
        description: "서브넷을 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            subnetNo: { type: "string", description: "서브넷 번호" },
          },
          required: ["subnetNo"],
        },
      },

      // ===== Network ACL =====
      {
        name: "list_network_acls",
        description: "Network ACL 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호 (선택사항)" },
            networkAclName: { type: "string", description: "Network ACL 이름으로 필터링" },
          },
        },
      },
      {
        name: "get_network_acl_detail",
        description: "Network ACL 상세 정보를 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            networkAclNo: { type: "string", description: "Network ACL 번호" },
          },
          required: ["networkAclNo"],
        },
      },
      {
        name: "create_network_acl",
        description: "Network ACL을 생성합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호" },
            networkAclName: { type: "string", description: "Network ACL 이름" },
            networkAclDescription: { type: "string", description: "Network ACL 설명" },
          },
          required: ["vpcNo"],
        },
      },
      {
        name: "delete_network_acl",
        description: "Network ACL을 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            networkAclNo: { type: "string", description: "Network ACL 번호" },
          },
          required: ["networkAclNo"],
        },
      },
      {
        name: "set_subnet_network_acl",
        description: "서브넷의 Network ACL을 설정합니다",
        inputSchema: {
          type: "object",
          properties: {
            subnetNo: { type: "string", description: "서브넷 번호" },
            networkAclNo: { type: "string", description: "적용할 Network ACL 번호" },
          },
          required: ["subnetNo", "networkAclNo"],
        },
      },
      {
        name: "get_network_acl_rule_list",
        description: "Network ACL의 룰 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            networkAclNo: { type: "string", description: "Network ACL 번호" },
          },
          required: ["networkAclNo"],
        },
      },
      {
        name: "add_network_acl_inbound_rule",
        description: "Network ACL에 인바운드 룰을 추가합니다",
        inputSchema: {
          type: "object",
          properties: {
            networkAclNo: { type: "string", description: "Network ACL 번호" },
            "networkAclRuleList.1.priority": { type: "string", description: "우선순위 (1~199, 낮을수록 높음)" },
            "networkAclRuleList.1.protocolTypeCode": { type: "string", description: "프로토콜 (TCP | UDP | ICMP)" },
            "networkAclRuleList.1.ipBlock": { type: "string", description: "IP 블록 (예: 0.0.0.0/0)" },
            "networkAclRuleList.1.ruleActionCode": { type: "string", description: "허용/차단 (ALLOW | DROP)" },
            "networkAclRuleList.1.portRange": { type: "string", description: "포트 범위 (예: 80, 80-443)" },
          },
          required: ["networkAclNo", "networkAclRuleList.1.priority", "networkAclRuleList.1.protocolTypeCode", "networkAclRuleList.1.ipBlock", "networkAclRuleList.1.ruleActionCode"],
        },
      },
      {
        name: "add_network_acl_outbound_rule",
        description: "Network ACL에 아웃바운드 룰을 추가합니다",
        inputSchema: {
          type: "object",
          properties: {
            networkAclNo: { type: "string", description: "Network ACL 번호" },
            "networkAclRuleList.1.priority": { type: "string", description: "우선순위 (1~199)" },
            "networkAclRuleList.1.protocolTypeCode": { type: "string", description: "프로토콜 (TCP | UDP | ICMP)" },
            "networkAclRuleList.1.ipBlock": { type: "string", description: "IP 블록 (예: 0.0.0.0/0)" },
            "networkAclRuleList.1.ruleActionCode": { type: "string", description: "허용/차단 (ALLOW | DROP)" },
            "networkAclRuleList.1.portRange": { type: "string", description: "포트 범위" },
          },
          required: ["networkAclNo", "networkAclRuleList.1.priority", "networkAclRuleList.1.protocolTypeCode", "networkAclRuleList.1.ipBlock", "networkAclRuleList.1.ruleActionCode"],
        },
      },
      {
        name: "remove_network_acl_inbound_rule",
        description: "Network ACL의 인바운드 룰을 제거합니다",
        inputSchema: {
          type: "object",
          properties: {
            networkAclNo: { type: "string", description: "Network ACL 번호" },
            "networkAclRuleList.1.priority": { type: "string", description: "우선순위" },
            "networkAclRuleList.1.protocolTypeCode": { type: "string", description: "프로토콜 (TCP | UDP | ICMP)" },
            "networkAclRuleList.1.ipBlock": { type: "string", description: "IP 블록" },
            "networkAclRuleList.1.ruleActionCode": { type: "string", description: "ALLOW | DROP" },
            "networkAclRuleList.1.portRange": { type: "string", description: "포트 범위" },
          },
          required: ["networkAclNo", "networkAclRuleList.1.priority", "networkAclRuleList.1.protocolTypeCode", "networkAclRuleList.1.ipBlock", "networkAclRuleList.1.ruleActionCode"],
        },
      },
      {
        name: "remove_network_acl_outbound_rule",
        description: "Network ACL의 아웃바운드 룰을 제거합니다",
        inputSchema: {
          type: "object",
          properties: {
            networkAclNo: { type: "string", description: "Network ACL 번호" },
            "networkAclRuleList.1.priority": { type: "string", description: "우선순위" },
            "networkAclRuleList.1.protocolTypeCode": { type: "string", description: "프로토콜 (TCP | UDP | ICMP)" },
            "networkAclRuleList.1.ipBlock": { type: "string", description: "IP 블록" },
            "networkAclRuleList.1.ruleActionCode": { type: "string", description: "ALLOW | DROP" },
            "networkAclRuleList.1.portRange": { type: "string", description: "포트 범위" },
          },
          required: ["networkAclNo", "networkAclRuleList.1.priority", "networkAclRuleList.1.protocolTypeCode", "networkAclRuleList.1.ipBlock", "networkAclRuleList.1.ruleActionCode"],
        },
      },

      // ===== NAT Gateway =====
      {
        name: "list_nat_gateway_instances",
        description: "NAT Gateway 인스턴스 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호 (선택사항)" },
            natGatewayName: { type: "string", description: "NAT Gateway 이름으로 필터링" },
          },
        },
      },
      {
        name: "get_nat_gateway_instance_detail",
        description: "NAT Gateway 인스턴스 상세 정보를 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            natGatewayInstanceNo: { type: "string", description: "NAT Gateway 인스턴스 번호" },
          },
          required: ["natGatewayInstanceNo"],
        },
      },
      {
        name: "create_nat_gateway_instance",
        description: "NAT Gateway 인스턴스를 생성합니다 (Public 서브넷 필요)",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호" },
            subnetNo: { type: "string", description: "서브넷 번호 (Public 서브넷)" },
            natGatewayName: { type: "string", description: "NAT Gateway 이름" },
            natGatewayDescription: { type: "string", description: "NAT Gateway 설명" },
          },
          required: ["vpcNo", "subnetNo"],
        },
      },
      {
        name: "delete_nat_gateway_instance",
        description: "NAT Gateway 인스턴스를 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            natGatewayInstanceNo: { type: "string", description: "NAT Gateway 인스턴스 번호" },
          },
          required: ["natGatewayInstanceNo"],
        },
      },

      // ===== Route Table =====
      {
        name: "list_route_tables",
        description: "라우트 테이블 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호 (선택사항)" },
            routeTableName: { type: "string", description: "라우트 테이블 이름으로 필터링" },
            supportedSubnetTypeCode: { type: "string", description: "서브넷 타입 (PUBLIC | PRIVATE)" },
          },
        },
      },
      {
        name: "get_route_table_detail",
        description: "라우트 테이블 상세 정보를 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            routeTableNo: { type: "string", description: "라우트 테이블 번호" },
          },
          required: ["routeTableNo"],
        },
      },
      {
        name: "create_route_table",
        description: "라우트 테이블을 생성합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호" },
            supportedSubnetTypeCode: { type: "string", description: "서브넷 타입 (PUBLIC | PRIVATE)" },
            routeTableName: { type: "string", description: "라우트 테이블 이름" },
            routeTableDescription: { type: "string", description: "라우트 테이블 설명" },
          },
          required: ["vpcNo", "supportedSubnetTypeCode"],
        },
      },
      {
        name: "delete_route_table",
        description: "라우트 테이블을 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            routeTableNo: { type: "string", description: "라우트 테이블 번호" },
          },
          required: ["routeTableNo"],
        },
      },
      {
        name: "get_route_list",
        description: "라우트 테이블의 라우트 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            routeTableNo: { type: "string", description: "라우트 테이블 번호" },
          },
          required: ["routeTableNo"],
        },
      },
      {
        name: "add_route",
        description: "라우트 테이블에 라우트를 추가합니다",
        inputSchema: {
          type: "object",
          properties: {
            routeTableNo: { type: "string", description: "라우트 테이블 번호" },
            "routeList.1.destinationCidrBlock": { type: "string", description: "목적지 CIDR (예: 0.0.0.0/0)" },
            "routeList.1.targetTypeCode": { type: "string", description: "타겟 타입 (NATGW | VPCPEERING | IGW)" },
            "routeList.1.targetNo": { type: "string", description: "타겟 번호 (NAT GW 번호 등)" },
            "routeList.1.targetName": { type: "string", description: "타겟 이름" },
          },
          required: ["routeTableNo", "routeList.1.destinationCidrBlock", "routeList.1.targetTypeCode", "routeList.1.targetNo", "routeList.1.targetName"],
        },
      },
      {
        name: "remove_route",
        description: "라우트 테이블의 라우트를 제거합니다",
        inputSchema: {
          type: "object",
          properties: {
            routeTableNo: { type: "string", description: "라우트 테이블 번호" },
            "routeList.1.destinationCidrBlock": { type: "string", description: "목적지 CIDR" },
            "routeList.1.targetTypeCode": { type: "string", description: "타겟 타입 (NATGW | VPCPEERING | IGW)" },
            "routeList.1.targetNo": { type: "string", description: "타겟 번호" },
            "routeList.1.targetName": { type: "string", description: "타겟 이름" },
          },
          required: ["routeTableNo", "routeList.1.destinationCidrBlock", "routeList.1.targetTypeCode", "routeList.1.targetNo", "routeList.1.targetName"],
        },
      },
      {
        name: "get_route_table_subnet_list",
        description: "라우트 테이블에 연관된 서브넷 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            routeTableNo: { type: "string", description: "라우트 테이블 번호" },
          },
          required: ["routeTableNo"],
        },
      },
      {
        name: "add_route_table_subnet",
        description: "라우트 테이블에 서브넷을 연결합니다",
        inputSchema: {
          type: "object",
          properties: {
            routeTableNo: { type: "string", description: "라우트 테이블 번호" },
            "subnetNoList.1": { type: "string", description: "연결할 서브넷 번호" },
          },
          required: ["routeTableNo", "subnetNoList.1"],
        },
      },
      {
        name: "remove_route_table_subnet",
        description: "라우트 테이블에서 서브넷 연결을 제거합니다",
        inputSchema: {
          type: "object",
          properties: {
            routeTableNo: { type: "string", description: "라우트 테이블 번호" },
            "subnetNoList.1": { type: "string", description: "제거할 서브넷 번호" },
          },
          required: ["routeTableNo", "subnetNoList.1"],
        },
      },

      // ===== VPC Peering =====
      {
        name: "list_vpc_peering_instances",
        description: "VPC Peering 인스턴스 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호 (선택사항)" },
            vpcPeeringName: { type: "string", description: "Peering 이름으로 필터링" },
          },
        },
      },
      {
        name: "create_vpc_peering_instance",
        description: "VPC Peering을 생성합니다 (두 VPC 간 연결 요청)",
        inputSchema: {
          type: "object",
          properties: {
            sourceVpcNo: { type: "string", description: "요청 VPC 번호" },
            targetVpcNo: { type: "string", description: "대상 VPC 번호" },
            vpcPeeringName: { type: "string", description: "Peering 이름" },
            vpcPeeringDescription: { type: "string", description: "Peering 설명" },
          },
          required: ["sourceVpcNo", "targetVpcNo"],
        },
      },
      {
        name: "delete_vpc_peering_instance",
        description: "VPC Peering 인스턴스를 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcPeeringInstanceNo: { type: "string", description: "VPC Peering 인스턴스 번호" },
          },
          required: ["vpcPeeringInstanceNo"],
        },
      },
      {
        name: "accept_or_reject_vpc_peering",
        description: "VPC Peering 요청을 수락하거나 거절합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcPeeringInstanceNo: { type: "string", description: "VPC Peering 인스턴스 번호" },
            isAccept: { type: "string", description: "수락 여부 (true | false)" },
          },
          required: ["vpcPeeringInstanceNo", "isAccept"],
        },
      },

      // ===== ACG =====
      {
        name: "list_acgs",
        description: "ACG(Access Control Group) 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호 (선택사항)" },
          },
        },
      },
      {
        name: "create_acg",
        description: "새로운 ACG를 생성합니다",
        inputSchema: {
          type: "object",
          properties: {
            accessControlGroupName: { type: "string", description: "ACG 이름" },
            vpcNo: { type: "string", description: "VPC 번호" },
            accessControlGroupDescription: { type: "string", description: "ACG 설명" },
          },
          required: ["accessControlGroupName", "vpcNo"],
        },
      },
      {
        name: "delete_acg",
        description: "ACG를 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            accessControlGroupNo: { type: "string", description: "ACG 번호" },
          },
          required: ["accessControlGroupNo"],
        },
      },
      {
        name: "get_acg_rule_list",
        description: "ACG의 인바운드/아웃바운드 규칙 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            accessControlGroupNo: { type: "string", description: "ACG 번호" },
          },
          required: ["accessControlGroupNo"],
        },
      },
      {
        name: "add_acg_inbound_rule",
        description: "ACG에 인바운드 규칙을 추가합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호" },
            accessControlGroupNo: { type: "string", description: "ACG 번호" },
            "accessControlGroupRuleList.1.protocolTypeCode": { type: "string", description: "프로토콜 (TCP | UDP | ICMP)" },
            "accessControlGroupRuleList.1.ipBlock": { type: "string", description: "IP 블록 (예: 0.0.0.0/0)" },
            "accessControlGroupRuleList.1.portRange": { type: "string", description: "포트 범위 (예: 80, 80-443)" },
          },
          required: ["vpcNo", "accessControlGroupNo", "accessControlGroupRuleList.1.protocolTypeCode"],
        },
      },
      {
        name: "add_acg_outbound_rule",
        description: "ACG에 아웃바운드 규칙을 추가합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호" },
            accessControlGroupNo: { type: "string", description: "ACG 번호" },
            "accessControlGroupRuleList.1.protocolTypeCode": { type: "string", description: "프로토콜 (TCP | UDP | ICMP)" },
            "accessControlGroupRuleList.1.ipBlock": { type: "string", description: "IP 블록 (예: 0.0.0.0/0)" },
            "accessControlGroupRuleList.1.portRange": { type: "string", description: "포트 범위 (예: 443, 1-65535)" },
          },
          required: ["vpcNo", "accessControlGroupNo", "accessControlGroupRuleList.1.protocolTypeCode"],
        },
      },
      {
        name: "remove_acg_inbound_rule",
        description: "ACG에서 인바운드 규칙을 제거합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호" },
            accessControlGroupNo: { type: "string", description: "ACG 번호" },
            "accessControlGroupRuleList.1.protocolTypeCode": { type: "string", description: "프로토콜 (TCP | UDP | ICMP)" },
            "accessControlGroupRuleList.1.ipBlock": { type: "string", description: "IP 블록" },
            "accessControlGroupRuleList.1.portRange": { type: "string", description: "포트 범위" },
          },
          required: ["vpcNo", "accessControlGroupNo", "accessControlGroupRuleList.1.protocolTypeCode"],
        },
      },
      {
        name: "remove_acg_outbound_rule",
        description: "ACG에서 아웃바운드 규칙을 제거합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호" },
            accessControlGroupNo: { type: "string", description: "ACG 번호" },
            "accessControlGroupRuleList.1.protocolTypeCode": { type: "string", description: "프로토콜 (TCP | UDP | ICMP)" },
            "accessControlGroupRuleList.1.ipBlock": { type: "string", description: "IP 블록" },
            "accessControlGroupRuleList.1.portRange": { type: "string", description: "포트 범위" },
          },
          required: ["vpcNo", "accessControlGroupNo", "accessControlGroupRuleList.1.protocolTypeCode"],
        },
      },

      // ===== Load Balancer =====
      {
        name: "list_load_balancers",
        description: "로드 밸런서 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호 (선택사항)" },
            loadBalancerName: { type: "string", description: "로드 밸런서 이름으로 필터링" },
            loadBalancerTypeCode: { type: "string", description: "타입 (APPLICATION | NETWORK | NETWORK_PROXY)" },
          },
        },
      },
      {
        name: "get_load_balancer_instance_detail",
        description: "로드 밸런서 인스턴스 상세 정보를 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            loadBalancerInstanceNo: { type: "string", description: "로드 밸런서 인스턴스 번호" },
          },
          required: ["loadBalancerInstanceNo"],
        },
      },
      {
        name: "create_load_balancer",
        description: "새로운 로드 밸런서를 생성합니다. 타깃 그룹을 먼저 생성 후 사용하세요",
        inputSchema: {
          type: "object",
          properties: {
            loadBalancerName: { type: "string", description: "로드 밸런서 이름" },
            loadBalancerTypeCode: { type: "string", description: "타입 (APPLICATION | NETWORK | NETWORK_PROXY)" },
            loadBalancerNetworkTypeCode: { type: "string", description: "네트워크 타입 (PUBLIC | PRIVATE)" },
            vpcNo: { type: "string", description: "VPC 번호" },
            "subnetNoList.1": { type: "string", description: "서브넷 번호" },
            "loadBalancerListenerList.1.protocolTypeCode": { type: "string", description: "리스너 프로토콜 (HTTP | HTTPS | TCP | TLS)" },
            "loadBalancerListenerList.1.port": { type: "string", description: "리스너 포트 (예: 80)" },
            "loadBalancerListenerList.1.targetGroupNo": { type: "string", description: "타깃 그룹 번호" },
            idleTimeout: { type: "string", description: "유휴 타임아웃 초 (기본값: 60)" },
            loadBalancerDescription: { type: "string", description: "로드 밸런서 설명" },
          },
          required: ["loadBalancerName", "loadBalancerTypeCode", "loadBalancerNetworkTypeCode", "vpcNo", "subnetNoList.1", "loadBalancerListenerList.1.protocolTypeCode", "loadBalancerListenerList.1.port", "loadBalancerListenerList.1.targetGroupNo"],
        },
      },
      {
        name: "change_load_balancer_instance_configuration",
        description: "로드 밸런서 인스턴스 설정을 변경합니다",
        inputSchema: {
          type: "object",
          properties: {
            loadBalancerInstanceNo: { type: "string", description: "로드 밸런서 인스턴스 번호" },
            idleTimeout: { type: "string", description: "유휴 타임아웃 초" },
            throughputTypeCode: { type: "string", description: "처리량 타입 (SMALL | MEDIUM | LARGE, NETWORK 타입만)" },
          },
          required: ["loadBalancerInstanceNo"],
        },
      },
      {
        name: "set_load_balancer_description",
        description: "로드 밸런서 설명을 수정합니다",
        inputSchema: {
          type: "object",
          properties: {
            loadBalancerInstanceNo: { type: "string", description: "로드 밸런서 인스턴스 번호" },
            loadBalancerDescription: { type: "string", description: "설명" },
          },
          required: ["loadBalancerInstanceNo", "loadBalancerDescription"],
        },
      },
      {
        name: "set_load_balancer_instance_subnet",
        description: "로드 밸런서의 서브넷을 설정합니다",
        inputSchema: {
          type: "object",
          properties: {
            loadBalancerInstanceNo: { type: "string", description: "로드 밸런서 인스턴스 번호" },
            "subnetNoList.1": { type: "string", description: "서브넷 번호" },
          },
          required: ["loadBalancerInstanceNo", "subnetNoList.1"],
        },
      },
      {
        name: "delete_load_balancer",
        description: "로드 밸런서 인스턴스를 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            loadBalancerInstanceNo: { type: "string", description: "로드 밸런서 인스턴스 번호" },
          },
          required: ["loadBalancerInstanceNo"],
        },
      },

      // ===== Load Balancer Listener =====
      {
        name: "get_load_balancer_listener_list",
        description: "로드 밸런서에 등록된 리스너 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            loadBalancerInstanceNo: { type: "string", description: "로드 밸런서 인스턴스 번호" },
          },
          required: ["loadBalancerInstanceNo"],
        },
      },
      {
        name: "create_load_balancer_listener",
        description: "로드 밸런서에 새로운 리스너를 생성합니다",
        inputSchema: {
          type: "object",
          properties: {
            loadBalancerInstanceNo: { type: "string", description: "로드 밸런서 인스턴스 번호" },
            protocolTypeCode: { type: "string", description: "프로토콜 (HTTP | HTTPS | TCP | UDP | TLS)" },
            port: { type: "string", description: "포트 번호 (1~65534)" },
            targetGroupNo: { type: "string", description: "타깃 그룹 번호" },
            useHttp2: { type: "string", description: "HTTP/2 사용 여부 true|false (HTTPS만)" },
            sslCertificateNo: { type: "string", description: "SSL 인증서 번호 (HTTPS/TLS 필수)" },
            tlsMinVersionTypeCode: { type: "string", description: "TLS 최소 버전 (TLSV10 | TLSV11 | TLSV12)" },
          },
          required: ["loadBalancerInstanceNo", "protocolTypeCode", "port", "targetGroupNo"],
        },
      },
      {
        name: "change_load_balancer_listener_configuration",
        description: "로드 밸런서 리스너 설정을 변경합니다",
        inputSchema: {
          type: "object",
          properties: {
            loadBalancerListenerNo: { type: "string", description: "리스너 번호" },
            protocolTypeCode: { type: "string", description: "프로토콜 (HTTP | HTTPS | TCP | UDP | TLS)" },
            port: { type: "string", description: "포트 (1~65534)" },
            useHttp2: { type: "string", description: "HTTP/2 사용 여부 true|false (HTTPS만)" },
            sslCertificateNo: { type: "string", description: "SSL 인증서 번호 (HTTPS/TLS 필수)" },
            tlsMinVersionTypeCode: { type: "string", description: "TLS 최소 버전 (TLSV10 | TLSV11 | TLSV12)" },
          },
          required: ["loadBalancerListenerNo", "protocolTypeCode", "port"],
        },
      },
      {
        name: "delete_load_balancer_listeners",
        description: "로드 밸런서 리스너를 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            loadBalancerListenerNo: { type: "string", description: "리스너 번호" },
          },
          required: ["loadBalancerListenerNo"],
        },
      },
      {
        name: "get_load_balancer_rule_list",
        description: "로드 밸런서 리스너의 규칙 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            loadBalancerListenerNo: { type: "string", description: "리스너 번호" },
          },
          required: ["loadBalancerListenerNo"],
        },
      },

      // ===== Target Group =====
      {
        name: "list_target_groups",
        description: "타깃 그룹 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호 (선택사항)" },
            targetGroupName: { type: "string", description: "타깃 그룹 이름으로 필터링" },
            targetTypeCode: { type: "string", description: "타깃 타입 (VSVR | SERVERGROUP)" },
          },
        },
      },
      {
        name: "get_target_group_detail",
        description: "타깃 그룹 상세 정보를 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            targetGroupNo: { type: "string", description: "타깃 그룹 번호" },
          },
          required: ["targetGroupNo"],
        },
      },
      {
        name: "create_target_group",
        description: "타깃 그룹을 생성합니다. 로드 밸런서 생성 전에 먼저 만들어야 합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호" },
            targetGroupName: { type: "string", description: "타깃 그룹 이름 (1~30자, 영문자로 시작, 영문자 또는 숫자로 끝)" },
            targetTypeCode: { type: "string", description: "타깃 타입 (VSVR)" },
            targetGroupProtocolTypeCode: { type: "string", description: "프로토콜 (HTTP | HTTPS | TCP | UDP | PROXY_TCP)" },
            targetGroupPort: { type: "string", description: "타깃 포트 (기본값: 80)" },
            targetGroupDescription: { type: "string", description: "설명" },
            healthCheckProtocolTypeCode: { type: "string", description: "헬스체크 프로토콜 (HTTP | HTTPS | TCP)" },
            healthCheckPort: { type: "string", description: "헬스체크 포트 (기본값: 80)" },
            healthCheckUrlPath: { type: "string", description: "헬스체크 URL 경로 (HTTP/HTTPS만, 예: /health)" },
            healthCheckHttpMethodTypeCode: { type: "string", description: "헬스체크 HTTP 메서드 (HEAD | GET) — HTTP/HTTPS 헬스체크 시 필수" },
            healthCheckCycle: { type: "string", description: "헬스체크 주기 초 (기본값: 30)" },
            healthCheckUpThreshold: { type: "string", description: "정상 판정 횟수 (기본값: 2)" },
            healthCheckDownThreshold: { type: "string", description: "비정상 판정 횟수 (기본값: 2)" },
          },
          required: ["vpcNo", "targetGroupProtocolTypeCode", "healthCheckProtocolTypeCode"],
        },
      },
      {
        name: "change_target_group_configuration",
        description: "타깃 그룹 설정을 변경합니다",
        inputSchema: {
          type: "object",
          properties: {
            targetGroupNo: { type: "string", description: "타깃 그룹 번호" },
            useStickySession: { type: "string", description: "세션별 접근 사용 여부 true|false (TCP/UDP/HTTP/HTTPS만)" },
            useProxyProtocol: { type: "string", description: "프록시 프로토콜 사용 여부 true|false (PROXY_TCP만)" },
            algorithmTypeCode: { type: "string", description: "알고리즘 (RR | SIPHS | LC | MH)" },
          },
          required: ["targetGroupNo"],
        },
      },
      {
        name: "change_target_group_health_check_configuration",
        description: "타깃 그룹 헬스체크 설정을 변경합니다",
        inputSchema: {
          type: "object",
          properties: {
            targetGroupNo: { type: "string", description: "타깃 그룹 번호" },
            healthCheckProtocolTypeCode: { type: "string", description: "프로토콜 (HTTP | HTTPS | TCP)" },
            healthCheckPort: { type: "string", description: "포트" },
            healthCheckUrlPath: { type: "string", description: "URL 경로" },
            healthCheckCycle: { type: "string", description: "주기 초" },
            healthCheckUpThreshold: { type: "string", description: "정상 판정 횟수" },
            healthCheckDownThreshold: { type: "string", description: "비정상 판정 횟수" },
          },
          required: ["targetGroupNo"],
        },
      },
      {
        name: "delete_target_groups",
        description: "타깃 그룹을 삭제합니다. 사용 중인 타깃 그룹은 삭제 불가합니다",
        inputSchema: {
          type: "object",
          properties: {
            targetGroupNo: { type: "string", description: "타깃 그룹 번호" },
          },
          required: ["targetGroupNo"],
        },
      },
      {
        name: "get_target_list",
        description: "타깃 그룹에 등록된 타깃(서버) 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            targetGroupNo: { type: "string", description: "타깃 그룹 번호" },
          },
          required: ["targetGroupNo"],
        },
      },
      {
        name: "add_target",
        description: "타깃 그룹에 서버를 추가합니다",
        inputSchema: {
          type: "object",
          properties: {
            targetGroupNo: { type: "string", description: "타깃 그룹 번호" },
            "targetNoList.1": { type: "string", description: "추가할 서버 인스턴스 번호" },
          },
          required: ["targetGroupNo", "targetNoList.1"],
        },
      },
      {
        name: "remove_target",
        description: "타깃 그룹에서 서버를 제거합니다",
        inputSchema: {
          type: "object",
          properties: {
            targetGroupNo: { type: "string", description: "타깃 그룹 번호" },
            "targetNoList.1": { type: "string", description: "제거할 서버 인스턴스 번호" },
          },
          required: ["targetGroupNo", "targetNoList.1"],
        },
      },

      // ===== Cloud DB (MySQL) =====
      {
        name: "list_cloud_dbs",
        description: "Cloud DB 인스턴스 목록을 조회합니다",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "create_cloud_db",
        description: "새로운 Cloud DB 인스턴스를 생성합니다",
        inputSchema: {
          type: "object",
          properties: {
            vpcNo: { type: "string", description: "VPC 번호" },
            subnetNo: { type: "string", description: "서브넷 번호" },
            cloudMysqlServiceName: { type: "string", description: "Cloud DB 서비스 이름 (3~30자)" },
            cloudMysqlServerNamePrefix: { type: "string", description: "서버 이름 접두사 (3~20자, 영문자로 시작)" },
            cloudMysqlUserName: { type: "string", description: "DB 접속 계정명 (3~16자, 영문자로 시작)" },
            cloudMysqlUserPassword: { type: "string", description: "DB 접속 비밀번호 (8~20자, 영문+숫자+특수문자 각 1자 이상)" },
            hostIp: { type: "string", description: "접속 허용 IP (전체: %, 특정 IP: 1.1.1.1)" },
            cloudMysqlDatabaseName: { type: "string", description: "기본 DB 이름 (1~30자, 영문자로 시작)" },
            cloudMysqlImageProductCode: { type: "string", description: "이미지 상품 코드 (미입력 시 최신 버전)" },
            cloudMysqlProductCode: { type: "string", description: "서버 스펙 상품 코드 (미입력 시 최소 사양)" },
            dataStorageTypeCode: { type: "string", description: "스토리지 타입 (SSD | HDD | CB2)" },
            isHa: { type: "boolean", description: "고가용성 여부 (기본값: true, true 시 서버 2대 생성)" },
            isMultiZone: { type: "boolean", description: "Multi Zone 여부 (isHa=true일 때 필수)" },
            isStorageEncryption: { type: "boolean", description: "스토리지 암호화 여부 (기본값: false)" },
            isBackup: { type: "boolean", description: "백업 여부 (기본값: true)" },
            backupFileRetentionPeriod: { type: "number", description: "백업 파일 보관 기간 (일, 기본값: 1)" },
            backupTime: { type: "string", description: "백업 시각 (예: 02:00, isAutomaticBackup=false일 때 필수)" },
            isAutomaticBackup: { type: "boolean", description: "백업 시점 자동 설정 여부 (기본값: true)" },
            cloudMysqlPort: { type: "number", description: "접속 포트 (기본값: 3306, 변경 시 10000~20000)" },
            standbyMasterSubnetNo: { type: "string", description: "Standby Master 서브넷 번호 (isMultiZone=true일 때 필수)" },
          },
          required: ["vpcNo", "subnetNo", "cloudMysqlServiceName", "cloudMysqlServerNamePrefix", "cloudMysqlUserName", "cloudMysqlUserPassword", "hostIp", "cloudMysqlDatabaseName"],
        },
      },
      {
        name: "delete_cloud_db",
        description: "Cloud DB 인스턴스를 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            cloudMysqlInstanceNo: { type: "string", description: "Cloud DB 인스턴스 번호" },
          },
          required: ["cloudMysqlInstanceNo"],
        },
      },
      {
        name: "list_cloud_db_mysql",
        description: "Cloud DB for MySQL 인스턴스 목록을 조회합니다",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "get_cloud_db_mysql_detail",
        description: "Cloud DB for MySQL 인스턴스 상세 정보를 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            cloudMysqlInstanceNo: { type: "string", description: "Cloud DB 인스턴스 번호" },
          },
          required: ["cloudMysqlInstanceNo"],
        },
      },

      // ===== Cloud DB Database =====
      {
        name: "get_cloud_mysql_database_list",
        description: "Cloud DB for MySQL 인스턴스의 Database 리스트 조회",
        inputSchema: {
          type: "object",
          properties: {
            cloudMysqlInstanceNo: { type: "string", description: "Cloud DB 인스턴스 번호" },
          },
          required: ["cloudMysqlInstanceNo"],
        },
      },
      {
        name: "add_cloud_mysql_database",
        description: "Cloud DB for MySQL 인스턴스에 Database 추가",
        inputSchema: {
          type: "object",
          properties: {
            cloudMysqlInstanceNo: { type: "string", description: "Cloud DB 인스턴스 번호" },
            "cloudMysqlDatabaseNameList.1": { type: "string", description: "추가할 DB 이름 (1~30자, 영문자로 시작, 영문자 또는 숫자로 끝)" },
          },
          required: ["cloudMysqlInstanceNo", "cloudMysqlDatabaseNameList.1"],
        },
      },
      {
        name: "delete_cloud_mysql_database",
        description: "Cloud DB for MySQL 인스턴스의 Database 삭제",
        inputSchema: {
          type: "object",
          properties: {
            cloudMysqlInstanceNo: { type: "string", description: "Cloud DB 인스턴스 번호" },
            "cloudMysqlDatabaseNameList.1": { type: "string", description: "삭제할 DB 이름" },
          },
          required: ["cloudMysqlInstanceNo", "cloudMysqlDatabaseNameList.1"],
        },
      },

      // ===== Cloud DB User =====
      {
        name: "get_cloud_mysql_user_list",
        description: "Cloud DB for MySQL 인스턴스의 DB User 리스트 조회",
        inputSchema: {
          type: "object",
          properties: {
            cloudMysqlInstanceNo: { type: "string", description: "Cloud DB 인스턴스 번호" },
          },
          required: ["cloudMysqlInstanceNo"],
        },
      },
      {
        name: "add_cloud_mysql_user",
        description: "Cloud DB for MySQL 인스턴스에 DB User 추가",
        inputSchema: {
          type: "object",
          properties: {
            cloudMysqlInstanceNo: { type: "string", description: "Cloud DB 인스턴스 번호" },
            "cloudMysqlUserList.1.name": { type: "string", description: "DB 유저명 (3~16자, 영문자로 시작, '-' '_' 허용)" },
            "cloudMysqlUserList.1.password": { type: "string", description: "비밀번호 (8~20자, 영문+숫자+특수문자 각 1자 이상)" },
            "cloudMysqlUserList.1.hostIp": { type: "string", description: "접속 허용 IP (전체: %, 특정 IP: 1.1.1.1, 대역: 1.1.1.%, CIDR: 1.1.1.0/24)" },
            "cloudMysqlUserList.1.authority": { type: "string", description: "DB User 권한: READ(조회만) | CRUD(입력/조회/수정/삭제) | DDL(테이블 생성/삭제/변경 포함)" },
            "cloudMysqlUserList.1.isSystemTableAccess": { type: "string", description: "시스템 테이블 접근 허용 여부 (true | false, 기본값: true)" },
          },
          required: ["cloudMysqlInstanceNo", "cloudMysqlUserList.1.name", "cloudMysqlUserList.1.password", "cloudMysqlUserList.1.hostIp", "cloudMysqlUserList.1.authority"],
        },
      },
      {
        name: "delete_cloud_mysql_user",
        description: "Cloud DB for MySQL 인스턴스의 DB User 삭제",
        inputSchema: {
          type: "object",
          properties: {
            cloudMysqlInstanceNo: { type: "string", description: "Cloud DB 인스턴스 번호" },
            "cloudMysqlUserList.1.name": { type: "string", description: "삭제할 유저명" },
            "cloudMysqlUserList.1.hostIp": { type: "string", description: "접속 허용 IP" },
          },
          required: ["cloudMysqlInstanceNo", "cloudMysqlUserList.1.name", "cloudMysqlUserList.1.hostIp"],
        },
      },

      // ===== Ncloud Object Storage (S3 호환) =====
      {
        name: "list_buckets",
        description: "Ncloud Object Storage 버킷 목록을 조회합니다",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "create_bucket",
        description: "Ncloud Object Storage 버킷을 생성합니다 (영문 소문자/숫자/-만, 3~63자)",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
          },
          required: ["bucket"],
        },
      },
      {
        name: "delete_bucket",
        description: "Ncloud Object Storage 버킷을 삭제합니다. 비어있는 버킷만 삭제 가능합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
          },
          required: ["bucket"],
        },
      },
      {
        name: "head_bucket",
        description: "버킷 존재 여부 및 접근 권한을 확인합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
          },
          required: ["bucket"],
        },
      },
      {
        name: "get_bucket_location",
        description: "버킷의 리전 정보를 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
          },
          required: ["bucket"],
        },
      },
      {
        name: "get_bucket_versioning",
        description: "버킷의 버전 관리 상태를 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
          },
          required: ["bucket"],
        },
      },
      {
        name: "put_bucket_versioning",
        description: "버킷의 버전 관리 상태를 활성화/중단합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
            status: { type: "string", description: "버전 관리 상태 (Enabled | Suspended)" },
          },
          required: ["bucket", "status"],
        },
      },
      {
        name: "get_bucket_lifecycle_configuration",
        description: "버킷의 수명주기 규칙을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
          },
          required: ["bucket"],
        },
      },
      {
        name: "delete_bucket_lifecycle",
        description: "버킷의 수명주기 규칙을 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
          },
          required: ["bucket"],
        },
      },
      {
        name: "get_bucket_encryption",
        description: "버킷의 암호화 정책을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
          },
          required: ["bucket"],
        },
      },
      {
        name: "list_objects",
        description: "버킷 내 객체 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
            prefix: { type: "string", description: "접두사 필터 (예: logs/)" },
            delimiter: { type: "string", description: "구분자 (예: /)" },
            maxKeys: { type: "string", description: "최대 반환 개수 (기본: 1000)" },
            marker: { type: "string", description: "페이징 시작 키" },
          },
          required: ["bucket"],
        },
      },
      {
        name: "list_objects_v2",
        description: "버킷 내 객체 목록을 조회합니다 (최신 버전, 페이징 토큰 지원)",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
            prefix: { type: "string", description: "접두사 필터" },
            delimiter: { type: "string", description: "구분자" },
            "max-keys": { type: "string", description: "최대 반환 개수" },
            "continuation-token": { type: "string", description: "다음 페이지 토큰" },
            "start-after": { type: "string", description: "이 키 이후부터 조회" },
          },
          required: ["bucket"],
        },
      },
      {
        name: "list_object_versions",
        description: "버전 관리 버킷의 객체 전체 버전 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
            prefix: { type: "string", description: "접두사 필터" },
            delimiter: { type: "string", description: "구분자" },
          },
          required: ["bucket"],
        },
      },
      {
        name: "head_object",
        description: "객체의 메타데이터를 조회합니다 (크기, 타입, 수정일 등)",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
            objectKey: { type: "string", description: "객체 키 (경로 포함, 예: folder/file.txt)" },
          },
          required: ["bucket", "objectKey"],
        },
      },
      {
        name: "get_object",
        description: "버킷에서 객체를 다운로드/조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
            objectKey: { type: "string", description: "객체 키" },
            versionId: { type: "string", description: "특정 버전 ID (버전 관리 버킷)" },
          },
          required: ["bucket", "objectKey"],
        },
      },
      {
        name: "put_object",
        description: "버킷에 텍스트/JSON 객체를 업로드합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
            objectKey: { type: "string", description: "객체 키 (경로 포함)" },
            body: { type: "string", description: "업로드할 텍스트 내용" },
            contentType: { type: "string", description: "Content-Type (기본: application/octet-stream)" },
          },
          required: ["bucket", "objectKey", "body"],
        },
      },
      {
        name: "copy_object",
        description: "버킷 내/간 객체를 복사합니다",
        inputSchema: {
          type: "object",
          properties: {
            sourceBucket: { type: "string", description: "원본 버킷 이름" },
            sourceKey: { type: "string", description: "원본 객체 키" },
            destBucket: { type: "string", description: "대상 버킷 이름" },
            destKey: { type: "string", description: "대상 객체 키" },
          },
          required: ["sourceBucket", "sourceKey", "destBucket", "destKey"],
        },
      },
      {
        name: "delete_object",
        description: "버킷에서 객체를 삭제합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
            objectKey: { type: "string", description: "객체 키" },
            versionId: { type: "string", description: "삭제할 특정 버전 ID" },
          },
          required: ["bucket", "objectKey"],
        },
      },
      {
        name: "create_multipart_upload",
        description: "대용량 파일의 멀티파트 업로드를 시작합니다. Upload ID를 반환합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
            objectKey: { type: "string", description: "객체 키" },
            contentType: { type: "string", description: "Content-Type" },
          },
          required: ["bucket", "objectKey"],
        },
      },
      {
        name: "list_multipart_uploads",
        description: "진행 중인 멀티파트 업로드 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
            prefix: { type: "string", description: "접두사 필터" },
          },
          required: ["bucket"],
        },
      },
      {
        name: "list_parts",
        description: "멀티파트 업로드의 업로드된 파트 목록을 조회합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
            objectKey: { type: "string", description: "객체 키" },
            uploadId: { type: "string", description: "Upload ID" },
          },
          required: ["bucket", "objectKey", "uploadId"],
        },
      },
      {
        name: "abort_multipart_upload",
        description: "진행 중인 멀티파트 업로드를 중단합니다",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", description: "버킷 이름" },
            objectKey: { type: "string", description: "객체 키" },
            uploadId: { type: "string", description: "Upload ID" },
          },
          required: ["bucket", "objectKey", "uploadId"],
        },
      },
    ],
  };
});

// 도구 실행 핸들러
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  try {
    const { name, arguments: args } = request.params;

    if (!args) {
      throw new Error("Arguments are required");
    }

    let result;

    switch (name) {
      // Server
      case "list_servers": {
        const typedArgs = args as {
          regionCode?: string; vpcNo?: string; serverName?: string;
          serverInstanceStatusCode?: string; pageNo?: string; pageSize?: string;
          sortedBy?: string; sortingOrder?: string;
        };
        result = await ncpClient.listServers(typedArgs);
        break;
      }
      case "get_server_detail": {
        const typedArgs = args as { serverInstanceNo: string };
        result = await ncpClient.getServerDetail(typedArgs.serverInstanceNo);
        break;
      }
      case "create_server": {
        const typedArgs = args as any;
        result = await ncpClient.createServer(typedArgs);
        break;
      }
      case "start_server": {
        const typedArgs = args as { serverInstanceNo: string };
        result = await ncpClient.startServer(typedArgs.serverInstanceNo);
        break;
      }
      case "stop_server": {
        const typedArgs = args as { serverInstanceNo: string };
        result = await ncpClient.stopServer(typedArgs.serverInstanceNo);
        break;
      }
      case "reboot_server": {
        const typedArgs = args as { serverInstanceNo: string };
        result = await ncpClient.rebootServer(typedArgs.serverInstanceNo);
        break;
      }
      case "delete_server": {
        const typedArgs = args as { serverInstanceNo: string };
        result = await ncpClient.deleteServer(typedArgs.serverInstanceNo);
        break;
      }
      case "change_server_spec": {
        const typedArgs = args as { serverInstanceNo: string; serverSpecCode: string };
        result = await ncpClient.changeServerSpec(typedArgs.serverInstanceNo, typedArgs.serverSpecCode);
        break;
      }
      case "set_protect_server_termination": {
        const typedArgs = args as { serverInstanceNo: string; isProtect: boolean };
        result = await ncpClient.setProtectServerTermination(typedArgs.serverInstanceNo, typedArgs.isProtect);
        break;
      }
      case "get_root_password": {
        const typedArgs = args as { serverInstanceNo: string; privateKey?: string };
        result = await ncpClient.getRootPassword(typedArgs.serverInstanceNo, typedArgs.privateKey);
        break;
      }

      // Server Image / Spec
      case "get_server_image_list": {
        const typedArgs = args as { regionCode?: string; hypervisorTypeCode?: string; pageNo?: string; pageSize?: string };
        result = await ncpClient.getServerImageList(typedArgs);
        break;
      }
      case "get_server_spec_list": {
        const typedArgs = args as { regionCode?: string; serverImageNo?: string; hypervisorTypeCodeList?: string };
        result = await ncpClient.getServerSpecList(typedArgs);
        break;
      }

      // Block Storage
      case "list_block_storages": {
        const typedArgs = args as { regionCode?: string; serverInstanceNo?: string; blockStorageName?: string; pageNo?: string; pageSize?: string };
        result = await ncpClient.listBlockStorages(typedArgs);
        break;
      }
      case "create_block_storage": {
        const typedArgs = args as { serverInstanceNo: string; blockStorageSize: string; blockStorageName?: string; blockStorageVolumeTypeCode?: string };
        result = await ncpClient.createBlockStorage(typedArgs);
        break;
      }
      case "delete_block_storage": {
        const typedArgs = args as { blockStorageInstanceNo: string };
        result = await ncpClient.deleteBlockStorage(typedArgs.blockStorageInstanceNo);
        break;
      }
      case "attach_block_storage": {
        const typedArgs = args as { serverInstanceNo: string; blockStorageInstanceNo: string };
        result = await ncpClient.attachBlockStorage(typedArgs.serverInstanceNo, typedArgs.blockStorageInstanceNo);
        break;
      }
      case "detach_block_storage": {
        const typedArgs = args as { blockStorageInstanceNo: string };
        result = await ncpClient.detachBlockStorage(typedArgs.blockStorageInstanceNo);
        break;
      }
      case "change_block_storage_volume_size": {
        const typedArgs = args as { blockStorageInstanceNo: string; blockStorageSize: string };
        result = await ncpClient.changeBlockStorageVolumeSize(typedArgs.blockStorageInstanceNo, typedArgs.blockStorageSize);
        break;
      }

      // Snapshot
      case "list_snapshots": {
        const typedArgs = args as { regionCode?: string; originalBlockStorageInstanceNo?: string; pageNo?: string; pageSize?: string };
        result = await ncpClient.listSnapshots(typedArgs);
        break;
      }
      case "create_snapshot": {
        const typedArgs = args as { blockStorageInstanceNo: string; blockStorageSnapshotName?: string; blockStorageSnapshotDescription?: string };
        result = await ncpClient.createSnapshot(typedArgs);
        break;
      }
      case "delete_snapshot": {
        const typedArgs = args as { blockStorageSnapshotInstanceNo: string };
        result = await ncpClient.deleteSnapshot(typedArgs.blockStorageSnapshotInstanceNo);
        break;
      }

      // Public IP
      case "list_public_ips": {
        const typedArgs = args as { regionCode?: string; isAssociated?: string };
        result = await ncpClient.listPublicIps(typedArgs);
        break;
      }
      case "create_public_ip": {
        const typedArgs = args as { serverInstanceNo?: string; regionCode?: string };
        result = await ncpClient.createPublicIp(typedArgs);
        break;
      }
      case "associate_public_ip": {
        const typedArgs = args as { publicIpInstanceNo: string; serverInstanceNo: string };
        result = await ncpClient.associatePublicIp(typedArgs.publicIpInstanceNo, typedArgs.serverInstanceNo);
        break;
      }
      case "disassociate_public_ip": {
        const typedArgs = args as { publicIpInstanceNo: string };
        result = await ncpClient.disassociatePublicIp(typedArgs.publicIpInstanceNo);
        break;
      }
      case "delete_public_ip": {
        const typedArgs = args as { publicIpInstanceNo: string };
        result = await ncpClient.deletePublicIp(typedArgs.publicIpInstanceNo);
        break;
      }

      // Init Script
      case "list_init_scripts": {
        const typedArgs = args as { regionCode?: string; initScriptName?: string; osTypeCode?: string };
        result = await ncpClient.listInitScripts(typedArgs);
        break;
      }
      case "create_init_script": {
        const typedArgs = args as { initScriptContent: string; initScriptName?: string; initScriptDescription?: string; osTypeCode?: string };
        result = await ncpClient.createInitScript(typedArgs);
        break;
      }
      case "delete_init_script": {
        const typedArgs = args as { initScriptNo: string };
        result = await ncpClient.deleteInitScript(typedArgs.initScriptNo);
        break;
      }

      // Network Interface
      case "list_network_interfaces": {
        const typedArgs = args as { regionCode?: string; vpcNo?: string; subnetNo?: string; networkInterfaceStatusCode?: string; serverInstanceNo?: string };
        result = await ncpClient.listNetworkInterfaces(typedArgs);
        break;
      }
      case "create_network_interface": {
        const typedArgs = args as any;
        result = await ncpClient.createNetworkInterface(typedArgs);
        break;
      }
      case "delete_network_interface": {
        const typedArgs = args as { networkInterfaceNo: string };
        result = await ncpClient.deleteNetworkInterface(typedArgs.networkInterfaceNo);
        break;
      }
      case "attach_network_interface": {
        const typedArgs = args as { networkInterfaceNo: string; serverInstanceNo: string; networkInterfaceOrder: string };
        result = await ncpClient.attachNetworkInterface(typedArgs.networkInterfaceNo, typedArgs.serverInstanceNo, typedArgs.networkInterfaceOrder);
        break;
      }
      case "detach_network_interface": {
        const typedArgs = args as { networkInterfaceNo: string; serverInstanceNo: string };
        result = await ncpClient.detachNetworkInterface(typedArgs.networkInterfaceNo, typedArgs.serverInstanceNo);
        break;
      }

      // VPC
      case "list_vpcs": {
        result = await ncpClient.listVpcs();
        break;
      }
      case "get_vpc_detail": {
        const typedArgs = args as { vpcNo: string };
        result = await ncpClient.getVpcDetail(typedArgs.vpcNo);
        break;
      }
      case "create_vpc": {
        const typedArgs = args as { vpcName: string; ipv4CidrBlock: string };
        result = await ncpClient.createVpc(typedArgs);
        break;
      }
      case "delete_vpc": {
        const typedArgs = args as { vpcNo: string };
        result = await ncpClient.deleteVpc(typedArgs.vpcNo);
        break;
      }

      // Subnet
      case "list_subnets": {
        const typedArgs = args as { vpcNo?: string };
        result = await ncpClient.listSubnets(typedArgs.vpcNo);
        break;
      }
      case "get_subnet_detail": {
        const typedArgs = args as { subnetNo: string };
        result = await ncpClient.getSubnetDetail(typedArgs.subnetNo);
        break;
      }
      case "create_subnet": {
        const typedArgs = args as { subnetName: string; vpcNo: string; subnet: string; zoneCode: string; networkAclNo: string; subnetTypeCode: string };
        result = await ncpClient.createSubnet(typedArgs);
        break;
      }
      case "delete_subnet": {
        const typedArgs = args as { subnetNo: string };
        result = await ncpClient.deleteSubnet(typedArgs.subnetNo);
        break;
      }

      // Network ACL
      case "list_network_acls": {
        const typedArgs = args as { vpcNo?: string; networkAclName?: string };
        result = await ncpClient.listNetworkAcls(typedArgs);
        break;
      }
      case "get_network_acl_detail": {
        const typedArgs = args as { networkAclNo: string };
        result = await ncpClient.getNetworkAclDetail(typedArgs.networkAclNo);
        break;
      }
      case "create_network_acl": {
        const typedArgs = args as { vpcNo: string; networkAclName?: string; networkAclDescription?: string };
        result = await ncpClient.createNetworkAcl(typedArgs);
        break;
      }
      case "delete_network_acl": {
        const typedArgs = args as { networkAclNo: string };
        result = await ncpClient.deleteNetworkAcl(typedArgs.networkAclNo);
        break;
      }
      case "set_subnet_network_acl": {
        const typedArgs = args as { subnetNo: string; networkAclNo: string };
        result = await ncpClient.setSubnetNetworkAcl(typedArgs);
        break;
      }
      case "get_network_acl_rule_list": {
        const typedArgs = args as { networkAclNo: string };
        result = await ncpClient.getNetworkAclRuleList(typedArgs.networkAclNo);
        break;
      }
      case "add_network_acl_inbound_rule": {
        const typedArgs = args as any;
        result = await ncpClient.addNetworkAclInboundRule(typedArgs);
        break;
      }
      case "add_network_acl_outbound_rule": {
        const typedArgs = args as any;
        result = await ncpClient.addNetworkAclOutboundRule(typedArgs);
        break;
      }
      case "remove_network_acl_inbound_rule": {
        const typedArgs = args as any;
        result = await ncpClient.removeNetworkAclInboundRule(typedArgs);
        break;
      }
      case "remove_network_acl_outbound_rule": {
        const typedArgs = args as any;
        result = await ncpClient.removeNetworkAclOutboundRule(typedArgs);
        break;
      }

      // NAT Gateway
      case "list_nat_gateway_instances": {
        const typedArgs = args as { vpcNo?: string; natGatewayName?: string; publicIp?: string };
        result = await ncpClient.listNatGatewayInstances(typedArgs);
        break;
      }
      case "get_nat_gateway_instance_detail": {
        const typedArgs = args as { natGatewayInstanceNo: string };
        result = await ncpClient.getNatGatewayInstanceDetail(typedArgs.natGatewayInstanceNo);
        break;
      }
      case "create_nat_gateway_instance": {
        const typedArgs = args as { vpcNo: string; subnetNo: string; natGatewayName?: string; natGatewayDescription?: string };
        result = await ncpClient.createNatGatewayInstance(typedArgs);
        break;
      }
      case "delete_nat_gateway_instance": {
        const typedArgs = args as { natGatewayInstanceNo: string };
        result = await ncpClient.deleteNatGatewayInstance(typedArgs.natGatewayInstanceNo);
        break;
      }

      // Route Table
      case "list_route_tables": {
        const typedArgs = args as { vpcNo?: string; routeTableName?: string; supportedSubnetTypeCode?: string };
        result = await ncpClient.listRouteTables(typedArgs);
        break;
      }
      case "get_route_table_detail": {
        const typedArgs = args as { routeTableNo: string };
        result = await ncpClient.getRouteTableDetail(typedArgs.routeTableNo);
        break;
      }
      case "create_route_table": {
        const typedArgs = args as { vpcNo: string; supportedSubnetTypeCode: string; routeTableName?: string; routeTableDescription?: string };
        result = await ncpClient.createRouteTable(typedArgs);
        break;
      }
      case "delete_route_table": {
        const typedArgs = args as { routeTableNo: string };
        result = await ncpClient.deleteRouteTable(typedArgs.routeTableNo);
        break;
      }
      case "get_route_list": {
        const typedArgs = args as { routeTableNo: string };
        result = await ncpClient.getRouteList(typedArgs.routeTableNo);
        break;
      }
      case "add_route": {
        const typedArgs = args as any;
        result = await ncpClient.addRoute(typedArgs);
        break;
      }
      case "remove_route": {
        const typedArgs = args as any;
        result = await ncpClient.removeRoute(typedArgs);
        break;
      }
      case "get_route_table_subnet_list": {
        const typedArgs = args as { routeTableNo: string };
        result = await ncpClient.getRouteTableSubnetList(typedArgs.routeTableNo);
        break;
      }
      case "add_route_table_subnet": {
        const typedArgs = args as any;
        result = await ncpClient.addRouteTableSubnet(typedArgs);
        break;
      }
      case "remove_route_table_subnet": {
        const typedArgs = args as any;
        result = await ncpClient.removeRouteTableSubnet(typedArgs);
        break;
      }

      // VPC Peering
      case "list_vpc_peering_instances": {
        const typedArgs = args as { vpcNo?: string; vpcPeeringName?: string };
        result = await ncpClient.listVpcPeeringInstances(typedArgs);
        break;
      }
      case "create_vpc_peering_instance": {
        const typedArgs = args as { sourceVpcNo: string; targetVpcNo: string; vpcPeeringName?: string; vpcPeeringDescription?: string };
        result = await ncpClient.createVpcPeeringInstance(typedArgs);
        break;
      }
      case "delete_vpc_peering_instance": {
        const typedArgs = args as { vpcPeeringInstanceNo: string };
        result = await ncpClient.deleteVpcPeeringInstance(typedArgs.vpcPeeringInstanceNo);
        break;
      }
      case "accept_or_reject_vpc_peering": {
        const typedArgs = args as { vpcPeeringInstanceNo: string; isAccept: string };
        result = await ncpClient.acceptOrRejectVpcPeering(typedArgs);
        break;
      }

      // ACG
      case "list_acgs": {
        const typedArgs = args as { vpcNo?: string };
        result = await ncpClient.listAcgs(typedArgs.vpcNo);
        break;
      }
      case "create_acg": {
        const typedArgs = args as { accessControlGroupName: string; vpcNo: string; accessControlGroupDescription?: string };
        result = await ncpClient.createAcg(typedArgs);
        break;
      }
      case "delete_acg": {
        const typedArgs = args as { accessControlGroupNo: string };
        result = await ncpClient.deleteAcg(typedArgs.accessControlGroupNo);
        break;
      }
      case "get_acg_rule_list": {
        const typedArgs = args as { accessControlGroupNo: string };
        result = await ncpClient.getAcgRuleList(typedArgs.accessControlGroupNo);
        break;
      }
      case "add_acg_inbound_rule": {
        const typedArgs = args as any;
        result = await ncpClient.addAcgInboundRule(typedArgs);
        break;
      }
      case "add_acg_outbound_rule": {
        const typedArgs = args as any;
        result = await ncpClient.addAcgOutboundRule(typedArgs);
        break;
      }
      case "remove_acg_inbound_rule": {
        const typedArgs = args as any;
        result = await ncpClient.removeAcgInboundRule(typedArgs);
        break;
      }
      case "remove_acg_outbound_rule": {
        const typedArgs = args as any;
        result = await ncpClient.removeAcgOutboundRule(typedArgs);
        break;
      }

      // Load Balancer
      case "list_load_balancers": {
        const typedArgs = args as { vpcNo?: string; loadBalancerName?: string; loadBalancerTypeCode?: string };
        result = await ncpClient.listLoadBalancers(typedArgs);
        break;
      }
      case "get_load_balancer_instance_detail": {
        const typedArgs = args as { loadBalancerInstanceNo: string };
        result = await ncpClient.getLoadBalancerInstanceDetail(typedArgs.loadBalancerInstanceNo);
        break;
      }
      case "create_load_balancer": {
        const typedArgs = args as any;
        result = await ncpClient.createLoadBalancer(typedArgs);
        break;
      }
      case "change_load_balancer_instance_configuration": {
        const typedArgs = args as any;
        result = await ncpClient.changeLoadBalancerInstanceConfiguration(typedArgs);
        break;
      }
      case "set_load_balancer_description": {
        const typedArgs = args as { loadBalancerInstanceNo: string; loadBalancerDescription: string };
        result = await ncpClient.setLoadBalancerDescription(typedArgs);
        break;
      }
      case "set_load_balancer_instance_subnet": {
        const typedArgs = args as any;
        result = await ncpClient.setLoadBalancerInstanceSubnet(typedArgs);
        break;
      }
      case "delete_load_balancer": {
        const typedArgs = args as { loadBalancerInstanceNo: string };
        result = await ncpClient.deleteLoadBalancer(typedArgs.loadBalancerInstanceNo);
        break;
      }

      // Load Balancer Listener
      case "get_load_balancer_listener_list": {
        const typedArgs = args as { loadBalancerInstanceNo: string };
        result = await ncpClient.getLoadBalancerListenerList(typedArgs.loadBalancerInstanceNo);
        break;
      }
      case "create_load_balancer_listener": {
        const typedArgs = args as any;
        result = await ncpClient.createLoadBalancerListener(typedArgs);
        break;
      }
      case "change_load_balancer_listener_configuration": {
        const typedArgs = args as any;
        result = await ncpClient.changeLoadBalancerListenerConfiguration(typedArgs);
        break;
      }
      case "delete_load_balancer_listeners": {
        const typedArgs = args as { loadBalancerListenerNo: string };
        result = await ncpClient.deleteLoadBalancerListeners(typedArgs.loadBalancerListenerNo);
        break;
      }
      case "get_load_balancer_rule_list": {
        const typedArgs = args as { loadBalancerListenerNo: string };
        result = await ncpClient.getLoadBalancerRuleList(typedArgs.loadBalancerListenerNo);
        break;
      }

      // Target Group
      case "list_target_groups": {
        const typedArgs = args as { vpcNo?: string; targetGroupName?: string; targetTypeCode?: string };
        result = await ncpClient.listTargetGroups(typedArgs);
        break;
      }
      case "get_target_group_detail": {
        const typedArgs = args as { targetGroupNo: string };
        result = await ncpClient.getTargetGroupDetail(typedArgs.targetGroupNo);
        break;
      }
      case "create_target_group": {
        const typedArgs = args as any;
        result = await ncpClient.createTargetGroup(typedArgs);
        break;
      }
      case "change_target_group_configuration": {
        const typedArgs = args as any;
        result = await ncpClient.changeTargetGroupConfiguration(typedArgs);
        break;
      }
      case "change_target_group_health_check_configuration": {
        const typedArgs = args as any;
        result = await ncpClient.changeTargetGroupHealthCheckConfiguration(typedArgs);
        break;
      }
      case "delete_target_groups": {
        const typedArgs = args as { targetGroupNo: string };
        result = await ncpClient.deleteTargetGroups(typedArgs.targetGroupNo);
        break;
      }
      case "get_target_list": {
        const typedArgs = args as { targetGroupNo: string };
        result = await ncpClient.getTargetList(typedArgs.targetGroupNo);
        break;
      }
      case "add_target": {
        const typedArgs = args as any;
        result = await ncpClient.addTarget(typedArgs);
        break;
      }
      case "remove_target": {
        const typedArgs = args as any;
        result = await ncpClient.removeTarget(typedArgs);
        break;
      }

      // Cloud DB
      case "list_cloud_dbs": {
        result = await ncpClient.listCloudDBInstances();
        break;
      }
      case "create_cloud_db": {
        const typedArgs = args as any;
        result = await ncpClient.createCloudDB(typedArgs);
        break;
      }
      case "delete_cloud_db": {
        const typedArgs = args as { cloudMysqlInstanceNo: string };
        result = await ncpClient.deleteCloudDB(typedArgs.cloudMysqlInstanceNo);
        break;
      }
      case "list_cloud_db_mysql": {
        result = await ncpClient.listCloudDBMysqlInstances();
        break;
      }
      case "get_cloud_db_mysql_detail": {
        const typedArgs = args as { cloudMysqlInstanceNo: string };
        result = await ncpClient.getCloudDBMysqlDetail(typedArgs.cloudMysqlInstanceNo);
        break;
      }

      // Cloud DB Database
      case "get_cloud_mysql_database_list": {
        const typedArgs = args as { cloudMysqlInstanceNo: string };
        result = await ncpClient.getCloudMysqlDatabaseList(typedArgs.cloudMysqlInstanceNo);
        break;
      }
      case "add_cloud_mysql_database": {
        const typedArgs = args as any;
        result = await ncpClient.addCloudMysqlDatabase(typedArgs);
        break;
      }
      case "delete_cloud_mysql_database": {
        const typedArgs = args as any;
        result = await ncpClient.deleteCloudMysqlDatabase(typedArgs);
        break;
      }

      // Cloud DB User
      case "get_cloud_mysql_user_list": {
        const typedArgs = args as { cloudMysqlInstanceNo: string };
        result = await ncpClient.getCloudMysqlUserList(typedArgs.cloudMysqlInstanceNo);
        break;
      }
      case "add_cloud_mysql_user": {
        const typedArgs = args as any;
        result = await ncpClient.addCloudMysqlUser(typedArgs);
        break;
      }
      case "delete_cloud_mysql_user": {
        const typedArgs = args as any;
        result = await ncpClient.deleteCloudMysqlUser(typedArgs);
        break;
      }

      // Object Storage (S3 호환)
      case "list_buckets": {
        result = await ncpClient.listBuckets();
        break;
      }
      case "create_bucket": {
        const typedArgs = args as { bucket: string };
        result = await ncpClient.createBucket(typedArgs.bucket);
        break;
      }
      case "delete_bucket": {
        const typedArgs = args as { bucket: string };
        result = await ncpClient.deleteBucket(typedArgs.bucket);
        break;
      }
      case "head_bucket": {
        const typedArgs = args as { bucket: string };
        result = await ncpClient.headBucket(typedArgs.bucket);
        break;
      }
      case "get_bucket_location": {
        const typedArgs = args as { bucket: string };
        result = await ncpClient.getBucketLocation(typedArgs.bucket);
        break;
      }
      case "get_bucket_versioning": {
        const typedArgs = args as { bucket: string };
        result = await ncpClient.getBucketVersioning(typedArgs.bucket);
        break;
      }
      case "put_bucket_versioning": {
        const typedArgs = args as { bucket: string; status: "Enabled" | "Suspended" };
        result = await ncpClient.putBucketVersioning(typedArgs.bucket, typedArgs.status);
        break;
      }
      case "get_bucket_lifecycle_configuration": {
        const typedArgs = args as { bucket: string };
        result = await ncpClient.getBucketLifecycleConfiguration(typedArgs.bucket);
        break;
      }
      case "delete_bucket_lifecycle": {
        const typedArgs = args as { bucket: string };
        result = await ncpClient.deleteBucketLifecycle(typedArgs.bucket);
        break;
      }
      case "get_bucket_encryption": {
        const typedArgs = args as { bucket: string };
        result = await ncpClient.getBucketEncryption(typedArgs.bucket);
        break;
      }
      case "list_objects": {
        const typedArgs = args as { bucket: string; prefix?: string; delimiter?: string; maxKeys?: string; marker?: string };
        const { bucket, ...params } = typedArgs;
        result = await ncpClient.listObjects(bucket, params);
        break;
      }
      case "list_objects_v2": {
        const typedArgs = args as any;
        const { bucket, ...params } = typedArgs;
        result = await ncpClient.listObjectsV2(bucket, params);
        break;
      }
      case "list_object_versions": {
        const typedArgs = args as { bucket: string; prefix?: string; delimiter?: string };
        const { bucket, ...params } = typedArgs;
        result = await ncpClient.listObjectVersions(bucket, params);
        break;
      }
      case "head_object": {
        const typedArgs = args as { bucket: string; objectKey: string };
        result = await ncpClient.headObject(typedArgs.bucket, typedArgs.objectKey);
        break;
      }
      case "get_object": {
        const typedArgs = args as { bucket: string; objectKey: string; versionId?: string };
        result = await ncpClient.getObject(typedArgs.bucket, typedArgs.objectKey, typedArgs.versionId);
        break;
      }
      case "put_object": {
        const typedArgs = args as { bucket: string; objectKey: string; body: string; contentType?: string };
        result = await ncpClient.putObject(typedArgs.bucket, typedArgs.objectKey, typedArgs.body, typedArgs.contentType);
        break;
      }
      case "copy_object": {
        const typedArgs = args as { sourceBucket: string; sourceKey: string; destBucket: string; destKey: string };
        result = await ncpClient.copyObject(typedArgs.sourceBucket, typedArgs.sourceKey, typedArgs.destBucket, typedArgs.destKey);
        break;
      }
      case "delete_object": {
        const typedArgs = args as { bucket: string; objectKey: string; versionId?: string };
        result = await ncpClient.deleteObject(typedArgs.bucket, typedArgs.objectKey, typedArgs.versionId);
        break;
      }
      case "create_multipart_upload": {
        const typedArgs = args as { bucket: string; objectKey: string; contentType?: string };
        result = await ncpClient.createMultipartUpload(typedArgs.bucket, typedArgs.objectKey, typedArgs.contentType);
        break;
      }
      case "list_multipart_uploads": {
        const typedArgs = args as { bucket: string; prefix?: string; delimiter?: string };
        const { bucket, ...params } = typedArgs;
        result = await ncpClient.listMultipartUploads(bucket, params);
        break;
      }
      case "list_parts": {
        const typedArgs = args as { bucket: string; objectKey: string; uploadId: string };
        result = await ncpClient.listParts(typedArgs.bucket, typedArgs.objectKey, typedArgs.uploadId);
        break;
      }
      case "abort_multipart_upload": {
        const typedArgs = args as { bucket: string; objectKey: string; uploadId: string };
        result = await ncpClient.abortMultipartUpload(typedArgs.bucket, typedArgs.objectKey, typedArgs.uploadId);
        break;
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (error: any) {
    return {
      content: [
        {
          type: "text",
          text: `Error: ${error.message}`,
        },
      ],
      isError: true,
    };
  }
});

// 서버 시작
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("NCP Extended MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
