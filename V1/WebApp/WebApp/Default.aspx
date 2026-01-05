<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Async="true" Inherits="WebApp.Default" %>

<!DOCTYPE html>
<html>
<head runat="server">
    <title>mTLS Client</title>
</head>
<body>
    <form id="form1" runat="server">

        <div>
            <asp:Label Text="Username:" runat="server" />
            <asp:TextBox ID="txtUserName" runat="server" />
        </div>

        <div>
            <asp:Label Text="Password:" runat="server" />
            <asp:TextBox ID="txtPassword" runat="server" TextMode="Password" />
        </div>

        <div>
            <asp:Button ID="btnCallApi" runat="server" Text="Call API" OnClick="btnCallApi_Click" />
        </div>

        <div>
            <asp:Label ID="lblResult" runat="server" />
        </div>

    </form>
</body>
</html>
