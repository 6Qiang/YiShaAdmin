using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.Reflection;
using Microsoft.AspNetCore.Mvc.Filters;
using Newtonsoft.Json;
using YiSha.Business.SystemManage;
using YiSha.Entity.SystemManage;
using YiSha.Enum;
using YiSha.Util;
using YiSha.Util.Extension;
using YiSha.Util.Model;
using YiSha.Web.Code;

namespace YiSha.Admin.WebApi.Controllers
{
    /// <summary>
    /// 验证token和记录日志
    /// </summary>
    public class AuthorizeFilterAttribute : ActionFilterAttribute
    {
        /// <summary>
        /// 忽略token的方法
        /// </summary>
        public static readonly string[] IgnoreToken = { "GetWxOpenId", "Login", "LoginOff" };
        private static readonly MenuAuthorizeBLL menuAuthorizeBLL = new MenuAuthorizeBLL();
        private static readonly MenuBLL menuBLL = new MenuBLL();

        /// <summary>
        /// 异步接口日志
        /// </summary>
        /// <param name="context"></param>
        /// <param name="next"></param>
        /// <returns></returns>
        public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();

            ActionExecutedContext resultContext = null;
            string token = context.HttpContext.Request.Headers["Authorization"].ParseToString();

            var actionName = context.ActionDescriptor.RouteValues["action"];

            OperatorInfo user = await Operator.Instance.Current(token);
            if (user != null)
            {

                #region 验证权限
                var temp = await menuAuthorizeBLL.GetAuthorizeList(user);
                // 获取当前请求的URL
                var url = context.HttpContext.Request.Path.ToString();
                var menu = menuBLL.GetEntity(url);
                if (menu != null && menu.Result.Data != null)
                {
                    var menuid = menu.Result.Data.Id;
                    var t = temp.Data.Where(w => w.MenuId == menuid).Any();
                    if (t)
                    {
                        //有授权
                    }
                    else
                    {
                        //未授权
                        //context.HttpContext.Response.StatusCode = 401;
                        TData obj = new TData();
                        obj.Tag = 0;
                        obj.Message = "抱歉，您没有权限";
                        context.Result = new JsonResult(obj);
                        return;
                    }
                }
                else
                {
                    //未授权
                    //context.HttpContext.Response.StatusCode = 401;
                    TData obj = new TData();
                    obj.Tag = 0;
                    obj.Message = "抱歉，您没有权限";
                    context.Result = new JsonResult(obj);
                    return;
                }
                #endregion
                resultContext = await next();
                // 根据传入的Token，设置CustomerId
                if (context.ActionArguments != null && context.ActionArguments.Count > 0)
                {
                    PropertyInfo property = context.ActionArguments.FirstOrDefault().Value.GetType().GetProperty("Token");
                    if (property != null)
                    {
                        property.SetValue(context.ActionArguments.FirstOrDefault().Value, token, null);
                    }
                    switch (context.HttpContext.Request.Method.ToUpper())
                    {
                        case "GET":
                            break;

                        case "POST":
                            property = context.ActionArguments.FirstOrDefault().Value.GetType().GetProperty("CustomerId");
                            if (property != null)
                            {
                                property.SetValue(context.ActionArguments.FirstOrDefault().Value, user.UserId, null);
                            }
                            break;
                    }
                }
            }
            else
            {
                if (IgnoreToken.Contains(actionName))
                {
                    resultContext = await next();
                }
                else
                {
                    context.HttpContext.Response.StatusCode = 401;
                    return;
                }

            }
            

            sw.Stop();

            #region 保存日志
            LogApiEntity logApiEntity = new LogApiEntity();
            logApiEntity.ExecuteUrl = context.HttpContext.Request.Path;
            logApiEntity.LogStatus = OperateStatusEnum.Success.ParseToInt();

            #region 获取Post参数
            switch (context.HttpContext.Request.Method.ToUpper())
            {
                case "GET":
                    logApiEntity.ExecuteParam = context.HttpContext.Request.QueryString.Value.ParseToString();
                    break;

                case "POST":
                    if (context.ActionArguments?.Count > 0)
                    {
                        logApiEntity.ExecuteUrl += context.HttpContext.Request.QueryString.Value.ParseToString();
                        logApiEntity.ExecuteParam = TextHelper.GetSubString(JsonConvert.SerializeObject(context.ActionArguments), 4000);
                    }
                    else
                    {
                        logApiEntity.ExecuteParam = context.HttpContext.Request.QueryString.Value.ParseToString();
                    }
                    break;
            }
            #endregion

            if (resultContext.Exception != null)
            {
                #region 异常获取
                StringBuilder sbException = new StringBuilder();
                Exception exception = resultContext.Exception;
                sbException.AppendLine(exception.Message);
                while (exception.InnerException != null)
                {
                    sbException.AppendLine(exception.InnerException.Message);
                    exception = exception.InnerException;
                }
                sbException.AppendLine(TextHelper.GetSubString(resultContext.Exception.StackTrace, 8000));
                #endregion

                logApiEntity.ExecuteResult = sbException.ToString();
                logApiEntity.LogStatus = OperateStatusEnum.Fail.ParseToInt();
            }
            else
            {
                ObjectResult result = context.Result as ObjectResult;
                if (result != null)
                {
                    logApiEntity.ExecuteResult = JsonConvert.SerializeObject(result.Value);
                    logApiEntity.LogStatus = OperateStatusEnum.Success.ParseToInt();
                }
            }
            if (user != null)
            {
                logApiEntity.BaseCreatorId = user.UserId;
            }
            logApiEntity.ExecuteParam = TextHelper.GetSubString(logApiEntity.ExecuteParam, 4000);
            logApiEntity.ExecuteResult = TextHelper.GetSubString(logApiEntity.ExecuteResult, 4000);
            logApiEntity.ExecuteTime = sw.ElapsedMilliseconds.ParseToInt();

            Action taskAction = async () =>
             {
                 // 让底层不用获取HttpContext
                 logApiEntity.BaseCreatorId = logApiEntity.BaseCreatorId ?? 0;

                 await new LogApiBLL().SaveForm(logApiEntity);
             };
            AsyncTaskHelper.StartTask(taskAction);
            #endregion
        }
    }
}
